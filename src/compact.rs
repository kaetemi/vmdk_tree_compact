//! Phase 2 (`compact`): rewrites each layer's sparse extents keeping only the grains some restorable
//! state still needs, verifies every rewritten extent against its original, and swaps it in.
//! Descriptors, `.vmsd`, `.vmx` and `.vmsn` files are never touched, so CID/parentCID stay as they are.

use crate::analysis::Bitset;
use crate::io::le32;
use crate::sparse::{SparseExtent, SparseHeader, FLAG_REDUNDANT_GT, GTE_ZERO_GRAIN, SECTOR_SIZE};
use crate::tree::Tree;
use anyhow::{ensure, Context, Result};
use std::fmt::Write as _;
use std::fs::OpenOptions;
use std::io::{BufWriter, Write};
use std::ops::Range;
use std::path::{Path, PathBuf};

pub const COMPACT_SUFFIX: &str = ".compact";
pub const OLD_SUFFIX: &str = ".old";
/// Byte offset of `uncleanShutdown` in the sparse extent header.
const UNCLEAN_SHUTDOWN_AT: usize = 72;
/// Grain data is copied and compared in batches of at most this many bytes.
const BATCH_BYTES: u64 = 16 << 20;

pub fn with_suffix(p: &Path, suffix: &str) -> PathBuf {
	let mut s = p.as_os_str().to_os_string();
	s.push(suffix);
	PathBuf::from(s)
}

fn exists(p: &Path) -> Result<bool> {
	p.try_exists().with_context(|| format!("checking whether {} exists", p.display()))
}

/// True if a grain table entry points at grain data (not unallocated, not a zero grain).
fn is_data(gte: u32, zero_ok: bool) -> bool {
	gte != 0 && !(gte == GTE_ZERO_GRAIN && zero_ok)
}

/// Where the grain tables of a hosted sparse extent live (sector numbers, in grain table order).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MetaLayout {
	/// Grain tables listed by the primary grain directory.
	pub gts: Vec<u64>,
	/// Grain tables listed by the redundant grain directory, if the extent has one.
	pub rgts: Option<Vec<u64>>,
}

impl MetaLayout {
	/// Reads both grain directories from the metadata area `meta` (`overHead` sectors) and checks that the
	/// layout is the one VMware writes, which the compacted extent reuses as is: no embedded descriptor,
	/// every grain table present and in ascending order, and the header, directories and tables pairwise
	/// disjoint inside the metadata area.
	pub fn parse(h: &SparseHeader, meta: &[u8]) -> Result<Self> {
		ensure!(
			h.descriptor_offset == 0 && h.descriptor_size == 0,
			"extent has an embedded descriptor (descriptorOffset {}, descriptorSize {}); compaction supports separate descriptors only",
			h.descriptor_offset,
			h.descriptor_size
		);
		ensure!(meta.len() as u64 == h.overhead * SECTOR_SIZE, "metadata area is {} bytes, overHead says {}", meta.len(), h.overhead * SECTOR_SIZE);
		let mut regions = vec![(0u64, 1u64, "header".to_string())];
		let gts = read_directory(h, meta, h.gd_offset, "primary", &mut regions)?;
		let rgts = if h.flags & FLAG_REDUNDANT_GT != 0 { Some(read_directory(h, meta, h.rgd_offset, "redundant", &mut regions)?) } else { None };
		regions.sort();
		for w in regions.windows(2) {
			ensure!(w[0].1 <= w[1].0, "{} (sectors {}..{}) and {} (sectors {}..{}) overlap", w[0].2, w[0].0, w[0].1, w[1].2, w[1].0, w[1].1);
		}
		Ok(Self { gts, rgts })
	}

	fn tables(&self) -> impl Iterator<Item = &[u64]> {
		std::iter::once(self.gts.as_slice()).chain(self.rgts.as_deref())
	}

	/// Writes `gtes` (one entry per grain of the extent) into every grain table of both directories.
	fn fill_tables(&self, h: &SparseHeader, meta: &mut [u8], gtes: &[u32]) {
		let per = h.num_gtes_per_gt as usize;
		for table in self.tables() {
			for (i, &s) in table.iter().enumerate() {
				for k in 0..per {
					let v = gtes.get(i * per + k).copied().unwrap_or(0);
					let o = (s * SECTOR_SIZE) as usize + k * 4;
					meta[o..o + 4].copy_from_slice(&v.to_le_bytes());
				}
			}
		}
	}

	/// True for every byte of the metadata area that belongs to a grain table.
	fn table_mask(&self, h: &SparseHeader, len: usize) -> Vec<bool> {
		let mut m = vec![false; len];
		let gt_bytes = h.gt_bytes() as usize;
		for table in self.tables() {
			for &s in table {
				let o = (s * SECTOR_SIZE) as usize;
				m[o..o + gt_bytes].fill(true);
			}
		}
		m
	}
}

fn read_directory(h: &SparseHeader, meta: &[u8], gd: u64, what: &str, regions: &mut Vec<(u64, u64, String)>) -> Result<Vec<u64>> {
	let num_gts = h.num_gts();
	let gd_sectors = (num_gts * 4).div_ceil(SECTOR_SIZE);
	let gt_sectors = h.gt_bytes().div_ceil(SECTOR_SIZE);
	ensure!(gd + gd_sectors <= h.overhead, "{what} grain directory at sector {gd} lies outside the metadata area (overHead {})", h.overhead);
	regions.push((gd, gd + gd_sectors, format!("{what} grain directory")));
	let mut gts: Vec<u64> = Vec::with_capacity(num_gts as usize);
	for i in 0..num_gts {
		let s = le32(meta, (gd * SECTOR_SIZE + i * 4) as usize) as u64;
		ensure!(s != 0, "{what} grain directory entry {i} is 0: grain table missing (VMware preallocates every grain table)");
		ensure!(s + gt_sectors <= h.overhead, "{what} grain table {i} at sector {s} lies outside the metadata area (overHead {})", h.overhead);
		if let Some(&prev) = gts.last() {
			ensure!(s > prev, "{what} grain tables are not in ascending order (table {i} at sector {s} follows sector {prev})");
		}
		regions.push((s, s + gt_sectors, format!("{what} grain table {i}")));
		gts.push(s);
	}
	Ok(gts)
}

/// Grain table of the compacted extent: kept data grains packed in logical grain order from `overHead`
/// upward, reclaimed and unallocated grains 0, kept zero grains still zero grains. Returns the entries and
/// the number of data grains.
pub fn compacted_gtes(h: &SparseHeader, gtes: &[u32], reclaim: &Bitset) -> Result<(Vec<u32>, u64)> {
	ensure!(reclaim.len() == gtes.len(), "reclaim set covers {} grains, the extent has {}", reclaim.len(), gtes.len());
	let zero_ok = h.zero_grain_supported();
	let mut out = vec![0u32; gtes.len()];
	let mut next = h.overhead;
	let mut data = 0u64;
	for (g, &e) in gtes.iter().enumerate() {
		if reclaim.get(g) {
			ensure!(e != 0, "grain {g} is marked reclaimable but is not allocated");
			continue;
		}
		if e == 0 {
			continue;
		}
		if !is_data(e, zero_ok) {
			out[g] = GTE_ZERO_GRAIN;
			continue;
		}
		out[g] = u32::try_from(next).context("compacted grain offset does not fit a 32-bit grain table entry")?;
		next += h.grain_size;
		data += 1;
	}
	Ok((out, data))
}

/// (original sector, compacted sector) of every data grain kept, in logical grain order.
fn data_pairs(h: &SparseHeader, orig: &[u32], new: &[u32]) -> Vec<(u64, u64)> {
	let zero_ok = h.zero_grain_supported();
	orig.iter().zip(new).filter(|(_, &n)| is_data(n, zero_ok)).map(|(&o, &n)| (o as u64, n as u64)).collect()
}

/// Splits the pairs into batches of at most `max` grains that are contiguous in both files.
fn batches(pairs: &[(u64, u64)], grain_sectors: u64, max: usize) -> Vec<Range<usize>> {
	let mut out = Vec::new();
	let mut i = 0;
	while i < pairs.len() {
		let mut j = i + 1;
		while j < pairs.len() && j - i < max && pairs[j].0 == pairs[j - 1].0 + grain_sectors && pairs[j].1 == pairs[j - 1].1 + grain_sectors {
			j += 1;
		}
		out.push(i..j);
		i = j;
	}
	out
}

fn batch_grains(h: &SparseHeader) -> usize {
	(BATCH_BYTES / (h.grain_size * SECTOR_SIZE)).max(1) as usize
}

/// What the writer produced.
pub struct Written {
	pub gtes: Vec<u32>,
	pub data_grains: u64,
	pub len: u64,
}

/// Writes the compacted copy of `orig` (opened on its own, so it still holds its grain tables) to `out`,
/// which must not exist. The metadata area is the original's byte for byte (header with `uncleanShutdown`
/// cleared, both grain directories, padding) apart from the grain table entries; kept data grains follow
/// from `overHead` in logical grain order. Written sequentially, then flushed and fsynced.
pub fn write_extent(orig: &SparseExtent, reclaim: &Bitset, out: &Path) -> Result<Written> {
	let h = &orig.header;
	ensure!(orig.gtes.len() as u64 == h.num_grains(), "{}: grain tables are not loaded", orig.path.display());
	let mut meta = orig.read_metadata()?;
	let layout = MetaLayout::parse(h, &meta).with_context(|| format!("{}: metadata layout", orig.path.display()))?;
	let (gtes, data_grains) = compacted_gtes(h, &orig.gtes, reclaim)?;
	meta[UNCLEAN_SHUTDOWN_AT] = 0;
	layout.fill_tables(h, &mut meta, &gtes);
	let gb = h.grain_size * SECTOR_SIZE;
	let len = h.overhead * SECTOR_SIZE + data_grains * gb;
	let pairs = data_pairs(h, &orig.gtes, &gtes);

	let file = OpenOptions::new().write(true).create_new(true).open(out).with_context(|| format!("creating {}", out.display()))?;
	let mut w = BufWriter::with_capacity(4 << 20, file);
	w.write_all(&meta).with_context(|| format!("writing {}", out.display()))?;
	let max = batch_grains(h);
	let mut buf = vec![0u8; max * gb as usize];
	for r in batches(&pairs, h.grain_size, max) {
		let n = r.len() * gb as usize;
		orig.read_data(pairs[r.start].0, &mut buf[..n])?;
		w.write_all(&buf[..n]).with_context(|| format!("writing {}", out.display()))?;
	}
	let file = w.into_inner().map_err(|e| e.into_error()).with_context(|| format!("flushing {}", out.display()))?;
	file.sync_all().with_context(|| format!("fsync {}", out.display()))?;
	let actual = file.metadata().with_context(|| format!("stat {}", out.display()))?.len();
	ensure!(actual == len, "{} is {actual} bytes after writing, expected {len}", out.display());
	Ok(Written { gtes, data_grains, len })
}

/// What the verifier found in the compacted extent.
pub struct Verified {
	pub gtes: Vec<u32>,
	pub data_grains: u64,
	pub len: u64,
}

/// Re-opens the compacted extent at `path` with the normal reader (so it passes every validation `tree`
/// applies) and checks it against the original and the reclaim set alone, independently of the writer:
/// header equal except `uncleanShutdown`; metadata outside the grain tables byte-identical; allocated set
/// equal to `alloc & !reclaim`; data grains packed in logical order from `overHead`; file length exactly
/// `overHead` + data grains; every kept grain byte-identical to the original.
pub fn verify_extent(orig: &SparseExtent, reclaim: &Bitset, path: &Path) -> Result<Verified> {
	let new = SparseExtent::open(path).context("re-opening with the normal reader")?;
	let h = &orig.header;
	let mut want = h.clone();
	want.unclean_shutdown = 0;
	ensure!(new.header == want, "header differs from the original: {:?} instead of {:?}", new.header, want);

	let mut a = orig.read_metadata()?;
	a[UNCLEAN_SHUTDOWN_AT] = 0;
	let b = new.read_metadata()?;
	ensure!(a.len() == b.len(), "metadata area is {} bytes, the original's {}", b.len(), a.len());
	let layout = MetaLayout::parse(h, &a).context("original metadata layout")?;
	ensure!(MetaLayout::parse(&new.header, &b).context("compacted metadata layout")? == layout, "grain table locations differ from the original");
	let mask = layout.table_mask(h, a.len());
	if let Some(i) = (0..a.len()).find(|&i| !mask[i] && a[i] != b[i]) {
		anyhow::bail!("metadata byte {i} (sector {}) outside the grain tables differs from the original ({:#04x} vs {:#04x})", i / 512, b[i], a[i]);
	}

	let n = orig.gtes.len();
	ensure!(reclaim.len() == n && new.gtes.len() == n, "grain counts differ: original {n}, compacted {}, reclaim set {}", new.gtes.len(), reclaim.len());
	let zero_ok = h.zero_grain_supported();
	let mut next = h.overhead;
	let mut pairs = Vec::new();
	for g in 0..n {
		let (o, e) = (orig.gtes[g], new.gtes[g]);
		ensure!(o != 0 || !reclaim.get(g), "grain {g} is marked reclaimable but is not allocated in the original");
		let keep = o != 0 && !reclaim.get(g);
		ensure!((e != 0) == keep, "grain {g}: grain table entry is {e}, expected {}", if keep { "allocated" } else { "unallocated (0)" });
		if !keep {
			continue;
		}
		ensure!(is_data(o, zero_ok) == is_data(e, zero_ok), "grain {g}: zero-grain status differs (entry {e}, original {o})");
		if is_data(e, zero_ok) {
			ensure!(e as u64 == next, "grain {g} is at sector {e}, expected {next} (kept grains packed in logical order from overHead)");
			pairs.push((o as u64, e as u64));
			next += h.grain_size;
		}
	}
	let len = next * SECTOR_SIZE;
	ensure!(new.file_len == len, "file is {} bytes, expected overHead + {} grains = {len}", new.file_len, pairs.len());

	let gb = (h.grain_size * SECTOR_SIZE) as usize;
	let max = batch_grains(h);
	let (mut ba, mut bb) = (vec![0u8; max * gb], vec![0u8; max * gb]);
	for r in batches(&pairs, h.grain_size, max) {
		let len = r.len() * gb;
		orig.read_data(pairs[r.start].0, &mut ba[..len])?;
		new.read_data(pairs[r.start].1, &mut bb[..len])?;
		if ba[..len] != bb[..len] {
			let k = (0..r.len()).find(|&k| ba[k * gb..(k + 1) * gb] != bb[k * gb..(k + 1) * gb]).unwrap_or(0);
			let (o, c) = pairs[r.start + k];
			anyhow::bail!("grain data at sector {c} differs from the original grain at sector {o}");
		}
	}
	Ok(Verified { gtes: new.gtes.clone(), data_grains: pairs.len() as u64, len })
}

/// One extent of a layer to compact, as planned from the analysis.
pub struct ExtentPlan {
	/// Extent file name (relative to the VM directory).
	pub file: String,
	pub start_grain: u64,
	pub grains: u64,
	pub orig_len: u64,
	pub new_len: u64,
	pub kept_data: u64,
	pub dropped_data: u64,
}

/// Everything needed to compact one layer after the analysis tree (and its open files) is gone.
pub struct LayerPlan {
	pub node: usize,
	pub depth: usize,
	pub file_name: String,
	pub label: String,
	pub selected: bool,
	/// Grain table entries at analysis time; the extents must still have exactly these when rewritten.
	pub gtes: Vec<u32>,
	pub reclaim: Bitset,
	pub extents: Vec<ExtentPlan>,
}

impl LayerPlan {
	/// Plans the layer of `node` and checks every extent's metadata layout up front.
	pub fn new(t: &Tree, node: usize, depth: usize, reclaim: &Bitset, selected: bool) -> Result<Self> {
		let l = &t.nodes[node].layer;
		ensure!(reclaim.is_subset_of(&l.alloc), "{}: reclaim set is not a subset of the allocated grains", l.file_name);
		let gb = l.grain_bytes();
		let mut extents = Vec::with_capacity(l.extents.len());
		for (le, line) in l.extents.iter().zip(&l.desc.extents) {
			let file = line.file.clone().with_context(|| format!("{}: extent line without a file name", l.file_name))?;
			let h = &le.extent.header;
			let meta = le.extent.read_metadata()?;
			MetaLayout::parse(h, &meta).with_context(|| format!("{file}: metadata layout"))?;
			let zero_ok = h.zero_grain_supported();
			let (mut kept, mut dropped) = (0u64, 0u64);
			for g in le.start_grain..le.start_grain + le.grains {
				if is_data(l.gte(g), zero_ok) {
					if reclaim.get(g as usize) {
						dropped += 1;
					} else {
						kept += 1;
					}
				}
			}
			extents.push(ExtentPlan {
				file,
				start_grain: le.start_grain,
				grains: le.grains,
				orig_len: le.extent.file_len,
				new_len: h.overhead * SECTOR_SIZE + kept * gb,
				kept_data: kept,
				dropped_data: dropped,
			});
		}
		Ok(Self { node, depth, file_name: l.file_name.clone(), label: t.label(node), selected, gtes: l.gtes().to_vec(), reclaim: reclaim.clone(), extents })
	}

	pub fn reclaim_grains(&self) -> u64 {
		self.reclaim.count()
	}

	pub fn orig_bytes(&self) -> u64 {
		self.extents.iter().map(|x| x.orig_len).sum()
	}

	pub fn new_bytes(&self) -> u64 {
		self.extents.iter().map(|x| x.new_len).sum()
	}

	/// The layer is rewritten only if it is selected and has something to drop.
	pub fn will_write(&self) -> bool {
		self.selected && !self.reclaim.is_empty()
	}
}

/// How far one extent of the layer being compacted has got.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Stage {
	Untouched,
	Written,
	Verified,
	OriginalMoved,
	Replaced,
	OldDeleted,
	OldKept,
}

impl Stage {
	fn describe(self) -> &'static str {
		match self {
			Stage::Untouched => "original untouched; no compacted copy",
			Stage::Written => "original untouched; .compact written but NOT verified",
			Stage::Verified => "original untouched; .compact written and verified",
			Stage::OriginalMoved => "original renamed to .old; .compact not yet renamed into place",
			Stage::Replaced => "verified compacted copy in place; original kept as .old",
			Stage::OldDeleted => "verified compacted copy in place; original deleted",
			Stage::OldKept => "verified compacted copy in place; original kept as .old (--keep-originals)",
		}
	}
}

/// Retries rename/delete briefly on sharing violations (e.g. a virus scanner looking at a new file).
fn fs_retry<T>(what: &dyn Fn() -> String, mut op: impl FnMut() -> std::io::Result<T>) -> Result<T> {
	let mut attempt = 0u64;
	loop {
		match op() {
			Ok(v) => return Ok(v),
			Err(e) if attempt < 5 && cfg!(windows) && matches!(e.raw_os_error(), Some(32 | 33)) => {
				attempt += 1;
				std::thread::sleep(std::time::Duration::from_millis(500 * attempt));
			}
			Err(e) => return Err(e).with_context(what),
		}
	}
}

/// Makes renames in the directory durable where the platform needs it (NTFS journals them itself).
fn sync_dir(dir: &Path) -> Result<()> {
	#[cfg(unix)]
	std::fs::File::open(dir).and_then(|d| d.sync_all()).with_context(|| format!("fsync directory {}", dir.display()))?;
	let _ = dir;
	Ok(())
}

pub fn check_no_locks(dir: &Path) -> Result<()> {
	for entry in std::fs::read_dir(dir).with_context(|| format!("listing {}", dir.display()))? {
		let name = entry?.file_name().to_string_lossy().into_owned();
		ensure!(!name.to_ascii_lowercase().ends_with(".lck"), "lock {name} found in {}: the VM appears to be running; stopping", dir.display());
	}
	Ok(())
}

/// Compacts one layer: for every extent, write `<extent>.compact` and verify it against the original;
/// then rename `<extent>` -> `<extent>.old` and `<extent>.compact` -> `<extent>` extent by extent,
/// re-open the swapped-in files, and delete the `.old` files unless `keep_originals`.
/// `stages` tracks every extent's progress so a failure can be reported exactly. `after_write` runs
/// after each `.compact` is written and synced, before it is verified (tests use it to inject damage).
pub fn compact_layer(
	dir: &Path,
	plan: &LayerPlan,
	keep_originals: bool,
	stages: &mut [Stage],
	after_write: &mut dyn FnMut(usize, &Path) -> Result<()>,
) -> Result<()> {
	ensure!(stages.len() == plan.extents.len(), "stage list does not match the extent list");
	let mut verified = Vec::with_capacity(plan.extents.len());
	for (i, x) in plan.extents.iter().enumerate() {
		let path = dir.join(&x.file);
		let out = with_suffix(&path, COMPACT_SUFFIX);
		let orig = SparseExtent::open(&path)?;
		let range = x.start_grain as usize..(x.start_grain + x.grains) as usize;
		ensure!(
			orig.file_len == x.orig_len && orig.gtes[..] == plan.gtes[range.clone()],
			"{} changed since the analysis (length {} vs {}, or different grain tables)",
			x.file,
			orig.file_len,
			x.orig_len
		);
		let reclaim = plan.reclaim.slice(range.start, range.len());
		let w = write_extent(&orig, &reclaim, &out).with_context(|| format!("writing {}", out.display()))?;
		stages[i] = Stage::Written;
		ensure!(
			w.len == x.new_len && w.data_grains == x.kept_data,
			"{} came out as {} bytes / {} data grains, the plan says {} / {}",
			out.display(),
			w.len,
			w.data_grains,
			x.new_len,
			x.kept_data
		);
		after_write(i, &out)?;
		let v = verify_extent(&orig, &reclaim, &out).with_context(|| format!("verifying {}", out.display()))?;
		ensure!(v.gtes == w.gtes && v.len == w.len, "{}: verified grain tables differ from the ones written", out.display());
		stages[i] = Stage::Verified;
		eprintln!("    {}: {} -> {} bytes, {} grains dropped, verified", x.file, x.orig_len, x.new_len, x.dropped_data);
		verified.push(v);
		// `orig` and the verifier's handle are closed here, before anything is renamed or deleted.
	}

	check_no_locks(dir)?;
	for (i, x) in plan.extents.iter().enumerate() {
		let path = dir.join(&x.file);
		let (out, old) = (with_suffix(&path, COMPACT_SUFFIX), with_suffix(&path, OLD_SUFFIX));
		ensure!(!exists(&old)?, "{} already exists; refusing to overwrite it", old.display());
		fs_retry(&|| format!("renaming {} to {}", path.display(), old.display()), || std::fs::rename(&path, &old))?;
		stages[i] = Stage::OriginalMoved;
		ensure!(!exists(&path)?, "{} still exists after renaming it", path.display());
		fs_retry(&|| format!("renaming {} to {}", out.display(), path.display()), || std::fs::rename(&out, &path))?;
		stages[i] = Stage::Replaced;
	}
	sync_dir(dir)?;

	// The files now in place must be the verified compacted ones before any original goes away.
	for (x, v) in plan.extents.iter().zip(&verified) {
		let e = SparseExtent::open(&dir.join(&x.file)).context("re-opening a swapped-in extent")?;
		ensure!(e.file_len == v.len && e.gtes == v.gtes, "{} is not the verified compacted extent after the rename", x.file);
	}

	for (i, x) in plan.extents.iter().enumerate() {
		if keep_originals {
			stages[i] = Stage::OldKept;
			continue;
		}
		let old = with_suffix(&dir.join(&x.file), OLD_SUFFIX);
		fs_retry(&|| format!("deleting {}", old.display()), || std::fs::remove_file(&old))?;
		stages[i] = Stage::OldDeleted;
	}
	sync_dir(dir)?;
	Ok(())
}

/// Per extent of the layer: how far it got, and which of its files are on disk right now.
pub fn describe_state(dir: &Path, plan: &LayerPlan, stages: &[Stage]) -> String {
	let mut s = String::new();
	let w = plan.extents.iter().map(|x| x.file.len()).max().unwrap_or(0);
	for (x, st) in plan.extents.iter().zip(stages) {
		let path = dir.join(&x.file);
		let mut present = Vec::new();
		for (p, label) in [
			(path.clone(), x.file.clone()),
			(with_suffix(&path, COMPACT_SUFFIX), format!("{}{COMPACT_SUFFIX}", x.file)),
			(with_suffix(&path, OLD_SUFFIX), format!("{}{OLD_SUFFIX}", x.file)),
		] {
			match p.try_exists() {
				Ok(true) => present.push(label),
				Ok(false) => {}
				Err(e) => present.push(format!("{label} (cannot check: {e})")),
			}
		}
		let present = if present.is_empty() { "NO FILE PRESENT".to_string() } else { present.join(", ") };
		writeln!(s, "  {:<w$}  {}; on disk: {present}", x.file, st.describe()).unwrap();
	}
	s
}

#[cfg(test)]
pub(crate) mod tests {
	use super::*;
	use crate::analysis;
	use crate::sparse::FLAG_ZERO_GRAIN_GTE;
	use crate::view::{ChainView, Disk};
	use std::collections::BTreeMap;

	pub struct Rng(pub u64);

	impl Rng {
		pub fn next(&mut self) -> u64 {
			self.0 ^= self.0 << 13;
			self.0 ^= self.0 >> 7;
			self.0 ^= self.0 << 17;
			self.0
		}

		pub fn below(&mut self, m: u64) -> u64 {
			self.next() % m
		}

		fn fill(&mut self, b: &mut [u8]) {
			for c in b.chunks_mut(8) {
				let v = self.next().to_le_bytes();
				c.copy_from_slice(&v[..c.len()]);
			}
		}
	}

	/// Grain size of the synthetic tree: 8 sectors (4 KiB), the smallest the reader accepts.
	pub const GS: u64 = 8;
	/// Grains per extent: three grain tables (the last one partly used) and one.
	pub const EXTENTS: [u64; 2] = [1100, 120];

	enum G {
		Data(Vec<u8>),
		Zero,
	}

	/// Writes a hosted sparse extent laid out like VMware's: header, redundant GD and GTs, primary GD and
	/// GTs, data grains from overHead in shuffled order. `pad` adds a marker byte in the padding before
	/// overHead, which the compacted copy must preserve.
	fn write_test_extent(path: &Path, grains: u64, flags: u32, entries: &[(u64, G)], rng: &mut Rng, pad: bool) {
		let num_gts = grains.div_ceil(512);
		let gd_sectors = (num_gts * 4).div_ceil(512);
		let (rgd, rgt0) = (1u64, 1 + gd_sectors);
		let gd = rgt0 + num_gts * 4;
		let gt0 = gd + gd_sectors;
		let meta_end = gt0 + num_gts * 4;
		let overhead = meta_end.div_ceil(GS) * GS + if pad { GS } else { 0 };
		let data: Vec<usize> = (0..entries.len()).filter(|&i| matches!(entries[i].1, G::Data(_))).collect();
		let mut order: Vec<usize> = (0..data.len()).collect();
		for i in (1..order.len()).rev() {
			order.swap(i, rng.below(i as u64 + 1) as usize);
		}
		let mut f = vec![0u8; ((overhead + data.len() as u64 * GS) * 512) as usize];
		f[0..4].copy_from_slice(b"KDMV");
		f[4..8].copy_from_slice(&1u32.to_le_bytes());
		f[8..12].copy_from_slice(&flags.to_le_bytes());
		f[12..20].copy_from_slice(&(grains * GS).to_le_bytes());
		f[20..28].copy_from_slice(&GS.to_le_bytes());
		f[44..48].copy_from_slice(&512u32.to_le_bytes());
		f[48..56].copy_from_slice(&rgd.to_le_bytes());
		f[56..64].copy_from_slice(&gd.to_le_bytes());
		f[64..72].copy_from_slice(&overhead.to_le_bytes());
		f[73..77].copy_from_slice(b"\n \r\n");
		let put = |f: &mut Vec<u8>, at: u64, v: u32| f[at as usize..at as usize + 4].copy_from_slice(&v.to_le_bytes());
		for t in 0..num_gts {
			put(&mut f, rgd * 512 + t * 4, (rgt0 + t * 4) as u32);
			put(&mut f, gd * 512 + t * 4, (gt0 + t * 4) as u32);
		}
		let mut slot = vec![0u64; entries.len()];
		for (k, &i) in data.iter().enumerate() {
			slot[i] = order[k] as u64;
		}
		for (i, (g, e)) in entries.iter().enumerate() {
			let gte = match e {
				G::Zero => 1u32,
				G::Data(bytes) => {
					let s = overhead + slot[i] * GS;
					f[(s * 512) as usize..((s + GS) * 512) as usize].copy_from_slice(bytes);
					s as u32
				}
			};
			put(&mut f, rgt0 * 512 + g * 4, gte);
			put(&mut f, gt0 * 512 + g * 4, gte);
		}
		if pad {
			f[(meta_end * 512) as usize] = 0xa5;
		}
		std::fs::write(path, f).unwrap();
	}

	/// Builds a four-layer VM in a fresh temp directory: base (snapshot 1) -> mid (snapshot 2) ->
	/// {leaf (snapshot 3), live}. Two extents per layer; the live layer's second extent uses zero grains.
	pub fn build_vm(name: &str, seed: u64) -> PathBuf {
		let dir = std::env::temp_dir().join(format!("vmdk_tree_compact_test_{name}_{}", std::process::id()));
		let _ = std::fs::remove_dir_all(&dir);
		std::fs::create_dir_all(&dir).unwrap();
		let mut rng = Rng(seed);
		let layers: [(&str, Option<usize>, u32); 4] = [
			("t.vmdk", None, 0x1111_1111),
			("t-000001.vmdk", Some(0), 0x2222_2222),
			("t-000002.vmdk", Some(1), 0x3333_3333),
			("t-000003.vmdk", Some(1), 0x4444_4444),
		];
		for (li, &(name, parent, cid)) in layers.iter().enumerate() {
			let stem = name.trim_end_matches(".vmdk");
			let parent_cid = parent.map_or("ffffffff".to_string(), |p| format!("{:08x}", layers[p].2));
			let mut desc =
				format!("# Disk DescriptorFile\nversion=1\nencoding=\"UTF-8\"\nCID={cid:08x}\nparentCID={parent_cid}\ncreateType=\"twoGbMaxExtentSparse\"\n");
			if let Some(p) = parent {
				desc += &format!("parentFileNameHint=\"{}\"\n", layers[p].0);
			}
			desc += "\n# Extent description\n";
			for (xi, &grains) in EXTENTS.iter().enumerate() {
				let file = format!("{stem}-s{:03}.vmdk", xi + 1);
				desc += &format!("RW {} SPARSE \"{file}\"\n", grains * GS);
				let zero = li == 3 && xi == 1;
				let flags = 3 | if zero { FLAG_ZERO_GRAIN_GTE } else { 0 };
				let mut entries = Vec::new();
				for g in 0..grains {
					let r = rng.below(100);
					if r < 45 {
						let mut b = vec![0u8; (GS * 512) as usize];
						rng.fill(&mut b);
						entries.push((g, G::Data(b)));
					} else if zero && r < 60 {
						entries.push((g, G::Zero));
					}
				}
				write_test_extent(&dir.join(&file), grains, flags, &entries, &mut rng, li == 0 && xi == 0);
			}
			std::fs::write(dir.join(name), desc).unwrap();
		}
		std::fs::write(dir.join("t.vmx"), "ide0:0.present = \"TRUE\"\nide0:0.fileName = \"t-000003.vmdk\"\n").unwrap();
		let mut vmsd = String::from("snapshot.numSnapshots = \"3\"\nsnapshot.current = \"2\"\n");
		for (i, name) in ["t.vmdk", "t-000001.vmdk", "t-000002.vmdk"].iter().enumerate() {
			vmsd += &format!("snapshot{i}.uid = \"{}\"\nsnapshot{i}.displayName = \"S{}\"\n", i + 1, i + 1);
			vmsd += &format!("snapshot{i}.disk0.fileName = \"{name}\"\nsnapshot{i}.disk0.node = \"ide0:0\"\n");
			if i > 0 {
				vmsd += &format!("snapshot{i}.parent = \"{i}\"\n");
			}
		}
		std::fs::write(dir.join("t.vmsd"), vmsd).unwrap();
		dir
	}

	/// Random fake NTFS free maps per node (the analysis takes bitsets, so no file system is needed).
	pub fn fake_free(t: &Tree, rng: &mut Rng) -> Vec<Bitset> {
		(0..t.len())
			.map(|_| {
				let mut b = Bitset::new(t.total_grains as usize);
				(0..t.total_grains as usize).filter(|_| rng.below(100) < 60).for_each(|g| b.set(g));
				b
			})
			.collect()
	}

	pub fn analyze_fake(t: &Tree, free: &[Bitset]) -> Vec<Bitset> {
		let alloc: Vec<Bitset> = t.nodes.iter().map(|n| n.layer.alloc.clone()).collect();
		analysis::analyze(&t.parents(), &t.children(), &alloc, free).unwrap()
	}

	pub fn files(dir: &Path) -> BTreeMap<String, Vec<u8>> {
		std::fs::read_dir(dir)
			.unwrap()
			.map(|e| {
				let e = e.unwrap();
				(e.file_name().to_string_lossy().into_owned(), std::fs::read(e.path()).unwrap())
			})
			.collect()
	}

	fn leftovers(dir: &Path) -> Vec<String> {
		files(dir).into_keys().filter(|n| n.ends_with(COMPACT_SUFFIX) || n.ends_with(OLD_SUFFIX)).collect()
	}

	#[test]
	fn compacts_synthetic_tree_end_to_end() {
		let dir = build_vm("e2e", 0x9e37_79b9_7f4a_7c15);
		let t = Tree::load(&dir).unwrap();
		let n = t.len();
		let free = fake_free(&t, &mut Rng(77));
		let reclaim = analyze_fake(&t, &free);
		let alloc: Vec<Bitset> = t.nodes.iter().map(|n| n.layer.alloc.clone()).collect();
		assert!(reclaim.iter().all(|r| !r.is_empty()), "every layer should have something to drop");
		assert!(t.nodes.iter().any(|n| n.layer.zero_gte_grains > 0), "the synthetic tree should contain zero grains");
		let gb = t.grain_bytes() as usize;
		let before: Vec<Vec<u8>> = (0..n)
			.map(|node| {
				let mut v = vec![0u8; t.capacity_bytes() as usize];
				ChainView::new(&t, node).read_at(0, &mut v).unwrap();
				v
			})
			.collect();
		let headers: BTreeMap<String, Vec<u8>> = files(&dir).into_iter().filter(|(k, _)| k.contains("-s0")).map(|(k, v)| (k, v[..512].to_vec())).collect();
		let plans: Vec<LayerPlan> = t.preorder().into_iter().map(|(node, d)| LayerPlan::new(&t, node, d, &reclaim[node], true).unwrap()).collect();
		let (parents, children) = (t.parents(), t.children());
		drop(t);

		for p in &plans {
			assert!(p.will_write());
			let mut stages = vec![Stage::Untouched; p.extents.len()];
			compact_layer(&dir, p, false, &mut stages, &mut |_, _| Ok(())).unwrap();
			assert!(stages.iter().all(|&s| s == Stage::OldDeleted));
		}
		assert!(leftovers(&dir).is_empty());

		// The compacted tree passes every validation of the normal reader.
		let t2 = Tree::load(&dir).unwrap();
		for node in 0..n {
			let mut want = alloc[node].clone();
			want.and_not_assign(&reclaim[node]);
			let l = &t2.nodes[node].layer;
			assert_eq!(l.alloc, want, "allocation of {}", l.file_name);
			assert_eq!(l.on_disk_bytes, l.overhead_bytes + l.data_grains * l.grain_bytes(), "{} has slack", l.file_name);
			assert!(l.on_disk_bytes < plans.iter().find(|p| p.node == node).unwrap().orig_bytes());
		}
		for (k, v) in &headers {
			assert_eq!(&std::fs::read(dir.join(k)).unwrap()[..512], &v[..], "header of {k}");
		}
		// 1100 grains: rgd 1, rgts 2..14, gd 14, gts 15..27, marker at sector 27, overHead 40.
		assert_eq!(std::fs::read(dir.join("t-s001.vmdk")).unwrap()[512 * 27], 0xa5, "metadata padding was not preserved");

		// Every grain a node does not consider free reads exactly as before.
		for node in 0..n {
			let view = ChainView::new(&t2, node);
			let mut buf = vec![0u8; gb];
			for g in (0..t2.total_grains as usize).filter(|&g| !free[node].get(g)) {
				view.read_at((g * gb) as u64, &mut buf).unwrap();
				assert!(buf[..] == before[node][g * gb..(g + 1) * gb], "node {node} grain {g} changed");
			}
		}

		// The simultaneous drop is a fixpoint.
		let alloc2: Vec<Bitset> = t2.nodes.iter().map(|n| n.layer.alloc.clone()).collect();
		let r2 = analysis::analyze(&parents, &children, &alloc2, &free).unwrap();
		assert!(r2.iter().all(|r| r.is_empty()));
		drop(t2);
		std::fs::remove_dir_all(&dir).unwrap();
	}

	/// Damages a written `.compact` file in one of several ways.
	fn damage(path: &Path, kind: u64) -> Result<()> {
		let mut f = std::fs::read(path)?;
		match kind {
			// One flipped bit in the last data grain.
			0 => *f.last_mut().unwrap() ^= 0x10,
			// Truncated by one sector.
			1 => f.truncate(f.len() - 512),
			// The first two data grains swapped in both grain tables: still a valid extent, wrong order.
			2 => {
				let h = SparseHeader::parse(&f)?;
				let layout = MetaLayout::parse(&h, &f[..(h.overhead * 512) as usize])?;
				for table in layout.tables() {
					let at: Vec<usize> =
						(0..h.num_grains() as usize).map(|g| (table[g / 512] * 512) as usize + (g % 512) * 4).filter(|&o| le32(&f, o) > 1).take(2).collect();
					let (a, b) = (le32(&f, at[0]), le32(&f, at[1]));
					f[at[0]..at[0] + 4].copy_from_slice(&b.to_le_bytes());
					f[at[1]..at[1] + 4].copy_from_slice(&a.to_le_bytes());
				}
			}
			// A header field changed (gdOffset moved by one sector).
			_ => f[56] += 1,
		}
		std::fs::write(path, f)?;
		Ok(())
	}

	#[test]
	fn damaged_compact_aborts_without_touching_originals() {
		for kind in 0..4 {
			let dir = build_vm(&format!("fail{kind}"), 1234 + kind);
			let t = Tree::load(&dir).unwrap();
			let free = fake_free(&t, &mut Rng(99 + kind));
			let reclaim = analyze_fake(&t, &free);
			let plan = LayerPlan::new(&t, t.root, 0, &reclaim[t.root], true).unwrap();
			drop(t);
			assert!(plan.will_write() && plan.extents[1].kept_data >= 2);
			let before = files(&dir);
			let mut stages = vec![Stage::Untouched; plan.extents.len()];
			let err = compact_layer(&dir, &plan, false, &mut stages, &mut |i, p| if i == 1 { damage(p, kind) } else { Ok(()) }).unwrap_err();
			assert!(format!("{err:#}").contains("verifying"), "kind {kind}: {err:#}");
			assert_eq!(stages, [Stage::Verified, Stage::Written], "kind {kind}");
			let after = files(&dir);
			for (name, bytes) in &before {
				assert!(after.get(name) == Some(bytes), "kind {kind}: {name} was modified");
			}
			assert_eq!(leftovers(&dir), ["t-s001.vmdk.compact", "t-s002.vmdk.compact"], "kind {kind}");
			let state = describe_state(&dir, &plan, &stages);
			assert!(state.contains("written and verified") && state.contains("NOT verified"), "{state}");
			std::fs::remove_dir_all(&dir).unwrap();
		}
	}

	#[test]
	fn rejects_unexpected_metadata_layouts() {
		let dir = build_vm("layout", 5);
		let path = dir.join("t-s001.vmdk");
		let orig = std::fs::read(&path).unwrap();
		let h = SparseHeader::parse(&orig).unwrap();
		let meta = &orig[..(h.overhead * 512) as usize];
		let layout = MetaLayout::parse(&h, meta).unwrap();
		assert_eq!(layout.gts.len(), 3);
		assert_eq!(layout.rgts.as_ref().unwrap().len(), 3);
		// Missing grain table.
		let mut m = meta.to_vec();
		m[(h.gd_offset * 512 + 4) as usize..(h.gd_offset * 512 + 8) as usize].fill(0);
		assert!(MetaLayout::parse(&h, &m).is_err());
		// Grain table overlapping the primary grain directory.
		let mut m = meta.to_vec();
		m[(h.gd_offset * 512) as usize..(h.gd_offset * 512 + 4) as usize].copy_from_slice(&(h.gd_offset as u32).to_le_bytes());
		assert!(MetaLayout::parse(&h, &m).is_err());
		// Embedded descriptor.
		let mut h2 = h.clone();
		h2.descriptor_offset = 1;
		h2.descriptor_size = 1;
		assert!(MetaLayout::parse(&h2, meta).is_err());
		std::fs::remove_dir_all(&dir).unwrap();
	}
}
