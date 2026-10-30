//! Snapshot tree: built from the descriptors (`parentFileNameHint` / `parentCID`, authoritative),
//! annotated with `.vmsd` snapshot names and the `.vmx` live leaf, and cross-validated against both.

use crate::descriptor::Descriptor;
use crate::io::{open_read_only, ReadAt};
use crate::layer::Layer;
use crate::sparse::{SparseHeader, HEADER_SIZE, SECTOR_SIZE};
use anyhow::{bail, ensure, Context, Result};
use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::path::{Path, PathBuf};

#[derive(Debug, Clone)]
pub struct Snapshot {
	pub uid: u64,
	pub parent_uid: Option<u64>,
	pub display_name: String,
	pub disk_file: String,
	pub disk_node: Option<String>,
}

pub struct Node {
	pub layer: Layer,
	pub parent: Option<usize>,
	pub children: Vec<usize>,
	pub snapshot: Option<Snapshot>,
	pub live: bool,
}

pub struct Tree {
	pub dir: PathBuf,
	pub nodes: Vec<Node>,
	pub root: usize,
	pub live: usize,
	/// VMX device key of the disk, e.g. `ide0:0`.
	pub disk_key: String,
	pub grain_sectors: u64,
	pub total_grains: u64,
	pub capacity_sectors: u64,
	pub extent_sectors: Vec<u64>,
	pub create_type: String,
	pub warnings: Vec<String>,
}

enum Classified {
	Descriptor(Descriptor),
	Extent,
	Unknown(String),
}

fn lower(s: &str) -> String {
	s.to_ascii_lowercase()
}

fn has_separator(s: &str) -> bool {
	s.contains('/') || s.contains('\\')
}

/// Distinguishes text descriptors, sparse extents with an embedded descriptor (monolithicSparse),
/// plain sparse extents and anything else.
fn classify(path: &Path) -> Result<Classified> {
	let file = open_read_only(path)?;
	let len = file.metadata()?.len();
	let mut head = vec![0u8; len.min(HEADER_SIZE as u64) as usize];
	file.read_full_at(0, &mut head)?;
	if head.starts_with(b"KDMV") {
		let h = SparseHeader::parse(&head)?;
		if h.descriptor_offset == 0 {
			return Ok(Classified::Extent);
		}
		ensure!(h.descriptor_size > 0 && h.descriptor_size <= 2048, "embedded descriptor size {} sectors is implausible", h.descriptor_size);
		let mut text = vec![0u8; (h.descriptor_size * SECTOR_SIZE) as usize];
		file.read_full_at(h.descriptor_offset * SECTOR_SIZE, &mut text)?;
		let end = text.iter().position(|&b| b == 0).unwrap_or(text.len());
		let s = std::str::from_utf8(&text[..end]).context("embedded descriptor is not UTF-8")?;
		return Ok(Classified::Descriptor(Descriptor::parse(s)?));
	}
	if head.starts_with(b"# Disk DescriptorFile") {
		ensure!(len <= 1 << 20, "descriptor file is {len} bytes; implausibly large");
		let mut text = vec![0u8; len as usize];
		file.read_full_at(0, &mut text)?;
		let s = std::str::from_utf8(&text).context("descriptor is not UTF-8")?;
		return Ok(Classified::Descriptor(Descriptor::parse(s)?));
	}
	Ok(Classified::Unknown(format!("{:02x?}", &head[..head.len().min(8)])))
}

fn read_text(path: &Path) -> Result<String> {
	let file = open_read_only(path)?;
	let len = file.metadata()?.len();
	ensure!(len <= 16 << 20, "{} is {len} bytes; implausibly large", path.display());
	let mut buf = vec![0u8; len as usize];
	file.read_full_at(0, &mut buf)?;
	Ok(String::from_utf8_lossy(&buf).into_owned())
}

/// Decodes VMware's `|XX` hex escapes in config values.
fn vmx_unescape(v: &str) -> String {
	let b = v.as_bytes();
	let mut out = Vec::with_capacity(b.len());
	let mut i = 0;
	while i < b.len() {
		if b[i] == b'|' && i + 2 < b.len() && b[i + 1].is_ascii_hexdigit() && b[i + 2].is_ascii_hexdigit() {
			out.push(u8::from_str_radix(&v[i + 1..i + 3], 16).unwrap());
			i += 3;
		} else {
			out.push(b[i]);
			i += 1;
		}
	}
	String::from_utf8_lossy(&out).into_owned()
}

/// Parses `key = "value"` config files (.vmx, .vmsd). Keys are lower-cased.
pub fn parse_kv(text: &str) -> Result<HashMap<String, String>> {
	let mut map = HashMap::new();
	for (i, raw) in text.lines().enumerate() {
		let line = raw.trim().trim_start_matches('\u{feff}');
		if line.is_empty() || line.starts_with('#') {
			continue;
		}
		let (k, v) = line.split_once('=').with_context(|| format!("line {}: expected key = value, got {line:?}", i + 1))?;
		let v = v.trim();
		let v = if v.len() >= 2 && v.starts_with('"') && v.ends_with('"') { &v[1..v.len() - 1] } else { v };
		let k = lower(k.trim());
		let v = vmx_unescape(v);
		if let Some(prev) = map.insert(k.clone(), v.clone()) {
			ensure!(prev == v, "line {}: key {k} appears twice with different values", i + 1);
		}
	}
	Ok(map)
}

fn parse_snapshots(kv: &HashMap<String, String>) -> Result<Vec<Snapshot>> {
	let mut by_idx: BTreeMap<u32, HashMap<String, String>> = BTreeMap::new();
	for (k, v) in kv {
		let Some(rest) = k.strip_prefix("snapshot") else { continue };
		let Some((idx, field)) = rest.split_once('.') else { continue };
		if idx.is_empty() || !idx.bytes().all(|b| b.is_ascii_digit()) {
			continue;
		}
		by_idx.entry(idx.parse()?).or_default().insert(field.to_string(), v.clone());
	}
	let mut out = Vec::new();
	for (idx, f) in by_idx {
		let get = |k: &str| f.get(k).with_context(|| format!("vmsd: snapshot{idx}.{k} is missing"));
		let uid: u64 = get("uid")?.parse().with_context(|| format!("vmsd: snapshot{idx}.uid"))?;
		let parent_uid = f.get("parent").map(|p| p.parse::<u64>()).transpose().with_context(|| format!("vmsd: snapshot{idx}.parent"))?;
		let display_name = f.get("displayname").cloned().unwrap_or_default();
		let num_disks: u32 = f.get("numdisks").map(|s| s.parse()).transpose().with_context(|| format!("vmsd: snapshot{idx}.numDisks"))?.unwrap_or(1);
		ensure!(num_disks == 1, "vmsd: snapshot{idx} ({display_name}) has {num_disks} disks; only single-disk VMs are supported");
		let disk_file = get("disk0.filename")?.clone();
		let disk_node = f.get("disk0.node").map(|s| lower(s));
		out.push(Snapshot { uid, parent_uid, display_name, disk_file, disk_node });
	}
	if let Some(n) = kv.get("snapshot.numsnapshots") {
		let n: usize = n.parse().context("vmsd: snapshot.numSnapshots")?;
		ensure!(n == out.len(), "vmsd: snapshot.numSnapshots is {n} but {} snapshots are listed", out.len());
	}
	Ok(out)
}

/// VMX virtual disks: `(ide|scsi|sata|nvme)N:M.fileName` naming a .vmdk on a present, non-CD-ROM device.
fn vmx_disks(vmx: &HashMap<String, String>) -> Vec<(String, String)> {
	let mut disks = Vec::new();
	for (k, v) in vmx {
		let Some(dev) = k.strip_suffix(".filename") else { continue };
		let bus_ok = ["ide", "scsi", "sata", "nvme"].iter().any(|bus| {
			dev.strip_prefix(*bus)
				.and_then(|r| r.split_once(':'))
				.is_some_and(|(a, b)| !a.is_empty() && !b.is_empty() && a.bytes().all(|c| c.is_ascii_digit()) && b.bytes().all(|c| c.is_ascii_digit()))
		});
		if !bus_ok || !lower(v).ends_with(".vmdk") {
			continue;
		}
		if vmx.get(&format!("{dev}.present")).is_some_and(|p| lower(p) == "false") {
			continue;
		}
		if vmx.get(&format!("{dev}.devicetype")).is_some_and(|t| lower(t).contains("cdrom")) {
			continue;
		}
		disks.push((dev.to_string(), v.clone()));
	}
	disks.sort();
	disks
}

impl Tree {
	pub fn load(dir: &Path) -> Result<Self> {
		ensure!(dir.is_dir(), "{} is not a directory", dir.display());
		let mut names = Vec::new();
		for entry in std::fs::read_dir(dir).with_context(|| format!("listing {}", dir.display()))? {
			let entry = entry?;
			names.push((entry.file_name().to_string_lossy().into_owned(), entry.file_type()?.is_dir()));
		}
		names.sort();
		if let Some((n, _)) = names.iter().find(|(n, _)| lower(n).ends_with(".lck")) {
			bail!("lock {n} found in {}: the VM appears to be running (or crashed); power it off cleanly first", dir.display());
		}
		let pick = |ext: &str| -> Vec<String> { names.iter().filter(|(n, d)| !d && lower(n).ends_with(ext)).map(|(n, _)| n.clone()).collect() };
		let vmx_files = pick(".vmx");
		ensure!(vmx_files.len() == 1, "expected exactly one .vmx in {}, found {:?}", dir.display(), vmx_files);
		let vmsd_files = pick(".vmsd");
		ensure!(vmsd_files.len() <= 1, "expected at most one .vmsd in {}, found {:?}", dir.display(), vmsd_files);

		let mut warnings = Vec::new();
		let mut descs: Vec<(String, Descriptor)> = Vec::new();
		let mut extent_files = Vec::new();
		let mut unknown = Vec::new();
		for n in pick(".vmdk") {
			match classify(&dir.join(&n)).with_context(|| format!("reading {n}"))? {
				Classified::Descriptor(d) => descs.push((n, d)),
				Classified::Extent => extent_files.push(n),
				Classified::Unknown(head) => unknown.push((n, head)),
			}
		}
		ensure!(!descs.is_empty(), "no VMDK descriptors found in {}", dir.display());
		let n = descs.len();
		let index: HashMap<String, usize> = descs.iter().enumerate().map(|(i, (name, _))| (lower(name), i)).collect();

		// Parent links from the descriptors.
		let mut parent: Vec<Option<usize>> = vec![None; n];
		for (i, (name, d)) in descs.iter().enumerate() {
			if !d.has_parent() {
				continue;
			}
			let hint = d.parent_hint.as_deref().with_context(|| format!("{name}: parentCID is {:08x} but there is no parentFileNameHint", d.parent_cid))?;
			ensure!(!has_separator(hint), "{name}: parentFileNameHint {hint:?} points outside the VM directory; not supported");
			let &p = index.get(&lower(hint)).with_context(|| format!("{name}: parent {hint:?} is not a descriptor in {}", dir.display()))?;
			ensure!(p != i, "{name} names itself as its parent");
			let (pname, pd) = &descs[p];
			ensure!(pd.cid == d.parent_cid, "{name}: parentCID {:08x} does not match CID {:08x} of its parent {pname}", d.parent_cid, pd.cid);
			parent[i] = Some(p);
		}
		let roots: Vec<usize> = (0..n).filter(|&i| parent[i].is_none()).collect();
		ensure!(
			roots.len() == 1,
			"expected exactly one base disk (parentCID ffffffff), found {}: {:?}",
			roots.len(),
			roots.iter().map(|&r| descs[r].0.as_str()).collect::<Vec<_>>()
		);
		let root = roots[0];
		for i in 0..n {
			let (mut cur, mut steps) = (i, 0);
			while let Some(p) = parent[cur] {
				cur = p;
				steps += 1;
				ensure!(steps <= n, "parent chain of {} loops", descs[i].0);
			}
			ensure!(cur == root, "{} does not descend from the base disk", descs[i].0);
		}

		// Every extent belongs to exactly one descriptor; report stray files.
		let mut referenced: HashMap<String, String> = HashMap::new();
		for (name, d) in &descs {
			for e in &d.extents {
				let Some(f) = &e.file else { continue };
				let k = lower(f);
				if let Some(prev) = referenced.insert(k.clone(), name.clone()) {
					bail!("extent {f} is referenced by both {prev} and {name}");
				}
				ensure!(k == lower(name) || !index.contains_key(&k), "{name}: extent {f} is itself a descriptor");
			}
		}
		for f in &extent_files {
			if !referenced.contains_key(&lower(f)) {
				warnings.push(format!("sparse extent {f} is not referenced by any descriptor (ignored)"));
			}
		}
		for (f, head) in &unknown {
			if !referenced.contains_key(&lower(f)) {
				warnings.push(format!("{f} is neither a descriptor nor a sparse extent (starts with {head}; ignored)"));
			}
		}

		// Open every layer (reads and validates all grain tables).
		let names_only: Vec<String> = descs.iter().map(|(n, _)| n.clone()).collect();
		let mut layers = Vec::with_capacity(n);
		for (name, d) in descs {
			layers.push(Layer::open(dir, &name, d)?);
		}

		// Identical geometry everywhere.
		let base = &layers[root];
		let extent_sectors: Vec<u64> = base.desc.extents.iter().map(|e| e.sectors).collect();
		for l in &layers {
			let sizes: Vec<u64> = l.desc.extents.iter().map(|e| e.sectors).collect();
			ensure!(sizes == extent_sectors, "{}: extent sizes {:?} differ from the base disk's {:?}", l.file_name, sizes, extent_sectors);
			ensure!(
				l.grain_sectors == base.grain_sectors,
				"{}: grain size {} differs from the base disk's {}",
				l.file_name,
				l.grain_sectors,
				base.grain_sectors
			);
			ensure!(l.capacity_sectors() == extent_sectors.iter().sum::<u64>(), "{}: capacity mismatch", l.file_name);
		}
		let grain_sectors = base.grain_sectors;
		let total_grains = base.total_grains;
		let capacity_sectors = base.capacity_sectors();
		let create_type = base.desc.create_type.clone();

		// .vmsd and .vmx.
		let vmx = parse_kv(&read_text(&dir.join(&vmx_files[0]))?).with_context(|| format!("parsing {}", vmx_files[0]))?;
		let vmsd = match vmsd_files.first() {
			Some(f) => Some(parse_kv(&read_text(&dir.join(f))?).with_context(|| format!("parsing {f}"))?),
			None => None,
		};
		let snapshots = match &vmsd {
			Some(kv) => parse_snapshots(kv)?,
			None => Vec::new(),
		};
		let disks = vmx_disks(&vmx);
		let snapshot_nodes: BTreeSet<String> = snapshots.iter().filter_map(|s| s.disk_node.clone()).collect();
		ensure!(snapshot_nodes.len() <= 1, "snapshots reference several disk devices {:?}; only single-disk VMs are supported", snapshot_nodes);
		ensure!(disks.len() == 1, "expected exactly one virtual disk in {}, found {:?}; only single-disk VMs are supported", vmx_files[0], disks);
		let (disk_key, live_file) = disks[0].clone();
		if let Some(k) = snapshot_nodes.first() {
			ensure!(*k == disk_key, "snapshots use disk device {k} but the .vmx disk is {disk_key}");
		}
		ensure!(!has_separator(&live_file), "{disk_key}.fileName {live_file:?} points outside the VM directory; not supported");
		let &live = index.get(&lower(&live_file)).with_context(|| format!("{disk_key}.fileName {live_file:?} is not a descriptor in {}", dir.display()))?;

		let mut children: Vec<Vec<usize>> = vec![Vec::new(); n];
		for i in 0..n {
			if let Some(p) = parent[i] {
				children[p].push(i);
			}
		}
		ensure!(children[live].is_empty(), "the live disk {live_file} has child layers");

		// Snapshots must map onto the descriptor tree exactly.
		let mut uid_node: HashMap<u64, usize> = HashMap::new();
		let mut snap_of: Vec<Option<Snapshot>> = vec![None; n];
		for s in &snapshots {
			ensure!(!has_separator(&s.disk_file), "snapshot {:?} disk {:?} is outside the VM directory; not supported", s.display_name, s.disk_file);
			let &ni = index
				.get(&lower(&s.disk_file))
				.with_context(|| format!("snapshot {:?} references {:?}, which is not a descriptor in the directory", s.display_name, s.disk_file))?;
			ensure!(ni != live, "snapshot {:?} references the live disk {}", s.display_name, live_file);
			ensure!(snap_of[ni].is_none(), "layer {} is the disk of more than one snapshot", names_only[ni]);
			ensure!(uid_node.insert(s.uid, ni).is_none(), "duplicate snapshot uid {}", s.uid);
			snap_of[ni] = Some(s.clone());
		}
		for s in &snapshots {
			let ni = uid_node[&s.uid];
			match s.parent_uid {
				None => ensure!(parent[ni].is_none(), "root snapshot {:?} uses {}, which has a parent layer", s.display_name, names_only[ni]),
				Some(pu) => {
					let &pn = uid_node.get(&pu).with_context(|| format!("snapshot {:?} has unknown parent uid {pu}", s.display_name))?;
					ensure!(
						parent[ni] == Some(pn),
						"snapshot {:?}: its disk {} has parent layer {}, but its parent snapshot uses {}",
						s.display_name,
						names_only[ni],
						parent[ni].map(|p| names_only[p].as_str()).unwrap_or("<none>"),
						names_only[pn]
					);
				}
			}
		}
		if let Some(cur) = vmsd.as_ref().and_then(|kv| kv.get("snapshot.current")) {
			let cur: u64 = cur.parse().context("vmsd: snapshot.current")?;
			let &cn = uid_node.get(&cur).with_context(|| format!("vmsd: snapshot.current {cur} is not a listed snapshot"))?;
			ensure!(
				parent[live] == Some(cn),
				"the live disk {live_file} has parent {}, but the current snapshot uses {}",
				parent[live].map(|p| names_only[p].as_str()).unwrap_or("<none>"),
				names_only[cn]
			);
		}
		for i in 0..n {
			if snap_of[i].is_none() && i != live {
				warnings.push(format!("layer {} is neither a snapshot disk nor the live disk; it is still treated as a restorable state", names_only[i]));
			}
		}

		let nodes = layers
			.into_iter()
			.enumerate()
			.map(|(i, layer)| Node { layer, parent: parent[i], children: children[i].clone(), snapshot: snap_of[i].take(), live: i == live })
			.collect();
		Ok(Self { dir: dir.to_path_buf(), nodes, root, live, disk_key, grain_sectors, total_grains, capacity_sectors, extent_sectors, create_type, warnings })
	}

	pub fn len(&self) -> usize {
		self.nodes.len()
	}

	pub fn grain_bytes(&self) -> u64 {
		self.grain_sectors * SECTOR_SIZE
	}

	pub fn capacity_bytes(&self) -> u64 {
		self.capacity_sectors * SECTOR_SIZE
	}

	/// Nodes in depth-first pre-order with their depth; children in file name order.
	pub fn preorder(&self) -> Vec<(usize, usize)> {
		let mut out = Vec::with_capacity(self.nodes.len());
		let mut stack = vec![(self.root, 0usize)];
		while let Some((n, d)) = stack.pop() {
			out.push((n, d));
			for &c in self.nodes[n].children.iter().rev() {
				stack.push((c, d + 1));
			}
		}
		out
	}

	/// The node itself followed by its ancestors up to the base disk.
	pub fn path_to_root(&self, n: usize) -> Vec<usize> {
		let mut path = vec![n];
		let mut cur = n;
		while let Some(p) = self.nodes[cur].parent {
			path.push(p);
			cur = p;
		}
		path
	}

	pub fn label(&self, n: usize) -> String {
		let node = &self.nodes[n];
		match (&node.snapshot, node.live) {
			(Some(s), _) => s.display_name.clone(),
			(None, true) => "<live>".to_string(),
			(None, false) => "<orphan>".to_string(),
		}
	}

	pub fn parents(&self) -> Vec<Option<usize>> {
		self.nodes.iter().map(|n| n.parent).collect()
	}

	pub fn children(&self) -> Vec<Vec<usize>> {
		self.nodes.iter().map(|n| n.children.clone()).collect()
	}
}

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn parses_vmsd_snapshots() {
		let kv = parse_kv(concat!(
			".encoding = \"UTF-8\"\n",
			"snapshot.numSnapshots = \"2\"\n",
			"snapshot.current = \"2\"\n",
			"snapshot0.uid = \"1\"\n",
			"snapshot0.displayName = \"Base |22SP3|22\"\n",
			"snapshot0.numDisks = \"1\"\n",
			"snapshot0.disk0.fileName = \"a.vmdk\"\n",
			"snapshot0.disk0.node = \"ide0:0\"\n",
			"snapshot1.uid = \"2\"\n",
			"snapshot1.parent = \"1\"\n",
			"snapshot1.displayName = \"Next\"\n",
			"snapshot1.disk0.fileName = \"a-000001.vmdk\"\n",
		))
		.unwrap();
		let s = parse_snapshots(&kv).unwrap();
		assert_eq!(s.len(), 2);
		assert_eq!(s[0].uid, 1);
		assert_eq!(s[0].parent_uid, None);
		assert_eq!(s[0].display_name, "Base \"SP3\"");
		assert_eq!(s[0].disk_node.as_deref(), Some("ide0:0"));
		assert_eq!(s[1].parent_uid, Some(1));
		assert_eq!(s[1].disk_file, "a-000001.vmdk");
	}

	#[test]
	fn finds_single_vmx_disk() {
		let kv = parse_kv(concat!(
			"ide0:0.fileName = \"x-000025.vmdk\"\n",
			"ide0:0.present = \"TRUE\"\n",
			"ide1:0.deviceType = \"cdrom-image\"\n",
			"ide1:0.fileName = \"C:\\iso\\a.iso\"\n",
			"scsi0:1.fileName = \"old.vmdk\"\n",
			"scsi0:1.present = \"FALSE\"\n",
		))
		.unwrap();
		assert_eq!(vmx_disks(&kv), vec![("ide0:0".to_string(), "x-000025.vmdk".to_string())]);
	}
}
