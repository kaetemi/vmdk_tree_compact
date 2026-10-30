//! Text output: tables, sizes and the per-subcommand reports.

use crate::tree::Tree;
use std::fmt::Write;

pub const MIB: u64 = 1 << 20;
pub const GIB: u64 = 1 << 30;

/// Human-readable size with one decimal: MiB below 1 GiB, GiB from there on.
pub fn size(bytes: u64) -> String {
	if bytes >= GIB {
		format!("{:.1} GiB", bytes as f64 / GIB as f64)
	} else {
		format!("{:.1} MiB", bytes as f64 / MIB as f64)
	}
}

/// Small byte quantities (cluster sizes, grain sizes).
pub fn unit(bytes: u64) -> String {
	if bytes >= MIB && bytes % MIB == 0 {
		format!("{} MiB", bytes / MIB)
	} else if bytes >= 1024 && bytes % 1024 == 0 {
		format!("{} KiB", bytes / 1024)
	} else {
		format!("{bytes} B")
	}
}

pub fn percent(part: u64, whole: u64) -> String {
	if whole == 0 {
		"-".to_string()
	} else {
		format!("{:.1}%", part as f64 * 100.0 / whole as f64)
	}
}

/// Column-aligned plain text table.
pub struct Table {
	headers: Vec<String>,
	right: Vec<bool>,
	rows: Vec<Option<Vec<String>>>,
}

impl Table {
	/// `cols`: (header, right-aligned).
	pub fn new(cols: &[(&str, bool)]) -> Self {
		Self { headers: cols.iter().map(|c| c.0.to_string()).collect(), right: cols.iter().map(|c| c.1).collect(), rows: Vec::new() }
	}

	pub fn row(&mut self, cells: Vec<String>) {
		assert_eq!(cells.len(), self.headers.len());
		self.rows.push(Some(cells));
	}

	pub fn rule(&mut self) {
		self.rows.push(None);
	}

	pub fn render(&self) -> String {
		let mut w: Vec<usize> = self.headers.iter().map(|h| h.chars().count()).collect();
		for r in self.rows.iter().flatten() {
			for (i, c) in r.iter().enumerate() {
				w[i] = w[i].max(c.chars().count());
			}
		}
		let total: usize = w.iter().sum::<usize>() + 2 * (w.len() - 1);
		let mut out = String::new();
		let line = |out: &mut String, cells: &[String]| {
			let mut s = String::new();
			for (i, c) in cells.iter().enumerate() {
				if i > 0 {
					s.push_str("  ");
				}
				let pad = w[i] - c.chars().count();
				if self.right[i] {
					s.push_str(&" ".repeat(pad));
					s.push_str(c);
				} else {
					s.push_str(c);
					s.push_str(&" ".repeat(pad));
				}
			}
			out.push_str(s.trim_end());
			out.push('\n');
		};
		line(&mut out, &self.headers);
		out.push_str(&"-".repeat(total));
		out.push('\n');
		for r in &self.rows {
			match r {
				Some(cells) => line(&mut out, cells),
				None => {
					out.push_str(&"-".repeat(total));
					out.push('\n');
				}
			}
		}
		out
	}
}

pub fn indent_name(depth: usize, name: &str) -> String {
	format!("{}{}", "  ".repeat(depth), name)
}

/// Common header describing the VM and disk geometry.
pub fn header(t: &Tree) -> String {
	let mut s = String::new();
	let snaps = t.nodes.iter().filter(|n| n.snapshot.is_some()).count();
	let orphans = t.nodes.iter().filter(|n| n.snapshot.is_none() && !n.live).count();
	writeln!(s, "VM directory : {}", t.dir.display()).unwrap();
	writeln!(s, "Virtual disk : {} -> {} (live leaf)", t.disk_key, t.nodes[t.live].layer.file_name).unwrap();
	writeln!(
		s,
		"Geometry     : {} sectors ({}), {}, {} extents per layer, grain {} sectors ({}), {} grains",
		t.capacity_sectors,
		size(t.capacity_bytes()),
		t.create_type,
		t.extent_sectors.len(),
		t.grain_sectors,
		unit(t.grain_bytes()),
		t.total_grains
	)
	.unwrap();
	writeln!(s, "Layers       : {} ({} snapshot disks, 1 live, {} orphans)", t.len(), snaps, orphans).unwrap();
	s
}

pub fn warnings(t: &Tree, extra: &[String]) -> String {
	let mut s = String::new();
	for w in t.warnings.iter().chain(extra) {
		writeln!(s, "WARNING: {w}").unwrap();
	}
	s
}

pub fn tree_report(t: &Tree) -> String {
	let gb = t.grain_bytes();
	let mut tab = Table::new(&[
		("Layer", false),
		("Snapshot", false),
		("CID", false),
		("Alloc grains", true),
		("Allocated", true),
		("On disk", true),
		("Metadata", true),
		("Slack bytes", true),
	]);
	let (mut ta, mut td, mut tm, mut ts) = (0u64, 0u64, 0u64, 0u64);
	for (n, depth) in t.preorder() {
		let l = &t.nodes[n].layer;
		let slack = l.on_disk_bytes - l.data_grains * gb - l.overhead_bytes;
		ta += l.allocated_grains();
		td += l.on_disk_bytes;
		tm += l.overhead_bytes;
		ts += slack;
		tab.row(vec![
			indent_name(depth, &l.file_name),
			t.label(n),
			format!("{:08x}", l.desc.cid),
			l.allocated_grains().to_string(),
			size(l.allocated_grains() * gb),
			size(l.on_disk_bytes),
			size(l.overhead_bytes),
			slack.to_string(),
		]);
	}
	tab.rule();
	tab.row(vec!["Total".into(), String::new(), String::new(), ta.to_string(), size(ta * gb), size(td), size(tm), ts.to_string()]);
	let mut s = header(t);
	s.push('\n');
	s.push_str(&tab.render());
	let zero: u64 = t.nodes.iter().map(|n| n.layer.zero_gte_grains).sum();
	writeln!(s).unwrap();
	writeln!(s, "Allocated grains: {ta} = {} bytes ({zero} of them zero-grain GTEs without data)", ta * gb).unwrap();
	writeln!(s, "Extent files on disk: {td} bytes (metadata {tm} bytes, slack {ts} bytes)").unwrap();
	let w = warnings(t, &[]);
	if !w.is_empty() {
		writeln!(s).unwrap();
		s.push_str(&w);
	}
	s
}

fn scheme_name(s: crate::partition::Scheme) -> &'static str {
	match s {
		crate::partition::Scheme::None => "none (no 55aa signature at LBA 0)",
		crate::partition::Scheme::Mbr => "MBR",
		crate::partition::Scheme::Gpt => "GPT",
		crate::partition::Scheme::Superfloppy => "none (NTFS volume at LBA 0)",
	}
}

pub fn ntfs_report(t: &Tree, fs: &[crate::ntfs::NodeFs]) -> String {
	let gb = t.grain_bytes();
	let mut s = header(t);
	let mut extra = Vec::new();
	for (n, depth) in t.preorder() {
		let f = &fs[n];
		let pad = "  ".repeat(depth);
		writeln!(s).unwrap();
		writeln!(s, "{pad}{} [{}]", t.nodes[n].layer.file_name, t.label(n)).unwrap();
		writeln!(s, "{pad}  partition table: {}", scheme_name(f.table.scheme)).unwrap();
		for p in &f.partitions {
			let pp = &p.partition;
			writeln!(s, "{pad}  #{} {}, LBA {} + {} sectors ({})", pp.number, pp.kind, pp.start_lba, pp.sectors, size(pp.size())).unwrap();
			match &p.volume {
				None => writeln!(s, "{pad}     not NTFS: treated as in use").unwrap(),
				Some(v) => {
					let b = &v.boot;
					writeln!(
						s,
						"{pad}     NTFS {}.{}, serial {:016x}, {} B/sector, {} clusters of {}, MFT at LCN {}, MFTMirr at LCN {}, {} records{}",
						v.ntfs_version.0,
						v.ntfs_version.1,
						b.serial,
						b.bytes_per_sector,
						v.clusters(),
						unit(v.cluster_bytes()),
						b.mft_lcn,
						b.mftmirr_lcn,
						unit(b.record_size),
						if v.mft_has_attribute_list { ", $MFT has an attribute list" } else { "" }
					)
					.unwrap();
					writeln!(
						s,
						"{pad}     $Bitmap: {} bytes; volume {} ({} bytes), used {}, free {} ({} bytes); {}",
						v.bitmap_data_size,
						size(v.total_bytes()),
						v.total_bytes(),
						size(v.used_clusters * v.cluster_bytes()),
						size(v.free_bytes()),
						v.free_bytes(),
						v.state()
					)
					.unwrap();
				}
			}
		}
		writeln!(s, "{pad}  free grains at this node: {} = {} ({} bytes)", f.free.count(), size(f.free.count() * gb), f.free.count() * gb).unwrap();
		extra.extend(f.warnings.iter().map(|w| format!("{} [{}]: {w}", t.nodes[n].layer.file_name, t.label(n))));
	}
	let w = warnings(t, &extra);
	if !w.is_empty() {
		writeln!(s).unwrap();
		s.push_str(&w);
	}
	s
}
