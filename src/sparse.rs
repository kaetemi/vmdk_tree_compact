//! Hosted sparse extent (`KDMV`) header and grain directory / grain table parsing,
//! following `SparseExtentHeader` from the VMware Virtual Disk Format 5.0 specification.

use crate::io::{le16, le32, le64, open_read_only, ReadAt};
use anyhow::{bail, ensure, Context, Result};
use std::fs::File;
use std::path::{Path, PathBuf};

pub const SECTOR_SIZE: u64 = 512;
pub const HEADER_SIZE: usize = 512;
pub const MAGIC: &[u8; 4] = b"KDMV";

pub const FLAG_VALID_NEWLINE_TEST: u32 = 1 << 0;
pub const FLAG_REDUNDANT_GT: u32 = 1 << 1;
pub const FLAG_ZERO_GRAIN_GTE: u32 = 1 << 2;
pub const FLAG_COMPRESSED: u32 = 1 << 16;
pub const FLAG_MARKERS: u32 = 1 << 17;

/// Grain table entry meaning "allocated, reads as zero" (only where the extent supports it).
pub const GTE_ZERO_GRAIN: u32 = 1;

/// Metadata regions up to this size are read in one go instead of table by table.
const MAX_CACHED_METADATA: u64 = 64 << 20;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SparseHeader {
	pub version: u32,
	pub flags: u32,
	pub capacity: u64,
	pub grain_size: u64,
	pub descriptor_offset: u64,
	pub descriptor_size: u64,
	pub num_gtes_per_gt: u32,
	pub rgd_offset: u64,
	pub gd_offset: u64,
	pub overhead: u64,
	pub unclean_shutdown: u8,
	pub newline_chars: [u8; 4],
	pub compress_algorithm: u16,
}

impl SparseHeader {
	/// Parses the packed little-endian header. Field layout (byte offsets):
	/// magic 0, version 4, flags 8, capacity 12, grainSize 20, descriptorOffset 28, descriptorSize 36,
	/// numGTEsPerGT 44, rgdOffset 48, gdOffset 56, overHead 64, uncleanShutdown 72,
	/// newline detection chars 73..77, compressAlgorithm 77.
	pub fn parse(b: &[u8]) -> Result<Self> {
		ensure!(b.len() >= HEADER_SIZE, "sparse extent header needs {HEADER_SIZE} bytes, got {}", b.len());
		ensure!(&b[0..4] == MAGIC, "bad sparse extent magic {:02x?} (expected \"KDMV\")", &b[0..4]);
		Ok(Self {
			version: le32(b, 4),
			flags: le32(b, 8),
			capacity: le64(b, 12),
			grain_size: le64(b, 20),
			descriptor_offset: le64(b, 28),
			descriptor_size: le64(b, 36),
			num_gtes_per_gt: le32(b, 44),
			rgd_offset: le64(b, 48),
			gd_offset: le64(b, 56),
			overhead: le64(b, 64),
			unclean_shutdown: b[72],
			newline_chars: [b[73], b[74], b[75], b[76]],
			compress_algorithm: le16(b, 77),
		})
	}

	pub fn validate(&self) -> Result<()> {
		ensure!(self.version == 1 || self.version == 2, "unsupported sparse extent version {}", self.version);
		ensure!(
			self.flags & (FLAG_COMPRESSED | FLAG_MARKERS) == 0 && self.compress_algorithm == 0,
			"compressed / stream-optimized extents are not supported (flags {:#x}, compressAlgorithm {})",
			self.flags,
			self.compress_algorithm
		);
		if self.flags & FLAG_VALID_NEWLINE_TEST != 0 {
			ensure!(
				self.newline_chars == *b"\n \r\n",
				"newline detection bytes are {:02x?} instead of 0a 20 0d 0a: the extent was corrupted by a text-mode transfer",
				self.newline_chars
			);
		}
		ensure!(self.grain_size >= 8 && self.grain_size.is_power_of_two(), "grain size {} sectors is not a power of two >= 8", self.grain_size);
		ensure!(self.num_gtes_per_gt == 512, "numGTEsPerGT is {} (hosted sparse extents use 512)", self.num_gtes_per_gt);
		ensure!(
			self.capacity > 0 && self.capacity % self.grain_size == 0,
			"capacity {} is not a positive multiple of the grain size {}",
			self.capacity,
			self.grain_size
		);
		ensure!(self.gd_offset != 0, "gdOffset is 0");
		if self.flags & FLAG_REDUNDANT_GT != 0 {
			ensure!(self.rgd_offset != 0, "redundant grain table flag set but rgdOffset is 0");
		}
		ensure!(self.overhead > 0, "overHead is 0");
		Ok(())
	}

	pub fn num_grains(&self) -> u64 {
		self.capacity / self.grain_size
	}

	pub fn num_gts(&self) -> u64 {
		self.capacity.div_ceil(self.grain_size * self.num_gtes_per_gt as u64)
	}

	pub fn gt_bytes(&self) -> u64 {
		self.num_gtes_per_gt as u64 * 4
	}

	pub fn zero_grain_supported(&self) -> bool {
		self.version >= 2 || self.flags & FLAG_ZERO_GRAIN_GTE != 0
	}
}

/// Serves reads from a cached copy of the start of the file where possible.
struct HeadCached<'a> {
	head: Vec<u8>,
	inner: &'a dyn ReadAt,
}

impl ReadAt for HeadCached<'_> {
	fn read_full_at(&self, offset: u64, buf: &mut [u8]) -> Result<()> {
		if offset + buf.len() as u64 <= self.head.len() as u64 {
			self.head.read_full_at(offset, buf)
		} else {
			self.inner.read_full_at(offset, buf)
		}
	}
}

/// Reads the grain directory at `gd_sector` and all grain tables it references.
/// Returns one entry per grain of the extent (0 = unallocated).
pub fn load_grain_tables(src: &dyn ReadAt, h: &SparseHeader, file_len: u64, gd_sector: u64, what: &str) -> Result<Vec<u32>> {
	let num_gts = h.num_gts();
	let per_gt = h.num_gtes_per_gt as u64;
	let num_grains = h.num_grains();
	let gd_bytes = num_gts * 4;
	ensure!(
		gd_sector + gd_bytes.div_ceil(SECTOR_SIZE) <= h.overhead,
		"{what} grain directory at sector {gd_sector} lies outside the metadata area (overHead {})",
		h.overhead
	);
	ensure!(gd_sector * SECTOR_SIZE + gd_bytes <= file_len, "{what} grain directory at sector {gd_sector} lies past the end of the file");
	let mut gd = vec![0u8; gd_bytes as usize];
	src.read_full_at(gd_sector * SECTOR_SIZE, &mut gd).with_context(|| format!("reading {what} grain directory"))?;
	let mut gtes = vec![0u32; num_grains as usize];
	let mut gt = vec![0u8; h.gt_bytes() as usize];
	for i in 0..num_gts {
		let gt_sector = le32(&gd, i as usize * 4) as u64;
		if gt_sector == 0 {
			// No grain table: every grain it would cover is unallocated.
			continue;
		}
		ensure!(
			gt_sector + h.gt_bytes().div_ceil(SECTOR_SIZE) <= h.overhead,
			"{what} grain table {i} at sector {gt_sector} lies outside the metadata area (overHead {})",
			h.overhead
		);
		ensure!(gt_sector * SECTOR_SIZE + h.gt_bytes() <= file_len, "{what} grain table {i} at sector {gt_sector} lies past the end of the file");
		src.read_full_at(gt_sector * SECTOR_SIZE, &mut gt).with_context(|| format!("reading {what} grain table {i}"))?;
		let first = i * per_gt;
		for j in 0..per_gt {
			let e = le32(&gt, j as usize * 4);
			if first + j < num_grains {
				gtes[(first + j) as usize] = e;
			} else {
				ensure!(e == 0, "{what} grain table {i} entry {j} lies beyond the extent capacity but is {e}");
			}
		}
	}
	Ok(gtes)
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct GteStats {
	/// Grains backed by data in the file.
	pub data_grains: u64,
	/// Grains marked as allocated zero grains (GTE 1, only where supported).
	pub zero_grains: u64,
}

/// Checks every grain table entry: grains must lie after the metadata, inside the file, and must not overlap.
pub fn validate_gtes(h: &SparseHeader, gtes: &[u32], file_len: u64) -> Result<GteStats> {
	let zero_ok = h.zero_grain_supported();
	let grain_bytes = h.grain_size * SECTOR_SIZE;
	let mut offsets = Vec::with_capacity(gtes.len());
	let mut stats = GteStats::default();
	for (g, &e) in gtes.iter().enumerate() {
		match e {
			0 => {}
			GTE_ZERO_GRAIN if zero_ok => stats.zero_grains += 1,
			GTE_ZERO_GRAIN => {
				bail!("grain {g} has GTE 1 (zero grain), but this version {} extent (flags {:#x}) does not support zero grains", h.version, h.flags)
			}
			_ => {
				let s = e as u64;
				ensure!(s >= h.overhead, "grain {g} at sector {s} overlaps the metadata area (overHead {})", h.overhead);
				ensure!(s * SECTOR_SIZE + grain_bytes <= file_len, "grain {g} at sector {s} extends past the end of the file ({file_len} bytes)");
				offsets.push(s);
			}
		}
	}
	offsets.sort_unstable();
	for w in offsets.windows(2) {
		ensure!(w[1] - w[0] >= h.grain_size, "grains at sectors {} and {} overlap", w[0], w[1]);
	}
	stats.data_grains = offsets.len() as u64;
	Ok(stats)
}

/// An opened, validated sparse extent with its grain tables in memory.
pub struct SparseExtent {
	pub path: PathBuf,
	file: File,
	pub file_len: u64,
	pub header: SparseHeader,
	pub gtes: Vec<u32>,
	pub stats: GteStats,
}

impl SparseExtent {
	pub fn open(path: &Path) -> Result<Self> {
		let file = open_read_only(path)?;
		let file_len = file.metadata().with_context(|| format!("stat {}", path.display()))?.len();
		let (header, gtes, stats) = Self::load(&file, file_len).with_context(|| format!("sparse extent {}", path.display()))?;
		Ok(Self { path: path.to_path_buf(), file, file_len, header, gtes, stats })
	}

	/// Parses and validates header and tables from any positioned reader.
	pub fn load(src: &dyn ReadAt, file_len: u64) -> Result<(SparseHeader, Vec<u32>, GteStats)> {
		ensure!(file_len >= HEADER_SIZE as u64, "file is only {file_len} bytes");
		let mut hb = [0u8; HEADER_SIZE];
		src.read_full_at(0, &mut hb)?;
		let header = SparseHeader::parse(&hb)?;
		header.validate()?;
		ensure!(header.unclean_shutdown == 0, "uncleanShutdown is set ({}): the extent was not closed cleanly", header.unclean_shutdown);
		let meta_len = (header.overhead * SECTOR_SIZE).min(file_len);
		let head = if meta_len <= MAX_CACHED_METADATA {
			let mut v = vec![0u8; meta_len as usize];
			src.read_full_at(0, &mut v)?;
			v
		} else {
			Vec::new()
		};
		let cached = HeadCached { head, inner: src };
		let gtes = load_grain_tables(&cached, &header, file_len, header.gd_offset, "primary")?;
		if header.flags & FLAG_REDUNDANT_GT != 0 {
			let redundant = load_grain_tables(&cached, &header, file_len, header.rgd_offset, "redundant")?;
			let diffs: Vec<usize> = gtes.iter().zip(&redundant).enumerate().filter(|(_, (a, b))| a != b).map(|(i, _)| i).collect();
			if let Some(&first) = diffs.first() {
				bail!("primary and redundant grain tables differ in {} entries (first at grain {first}: {} vs {})", diffs.len(), gtes[first], redundant[first]);
			}
		}
		let stats = validate_gtes(&header, &gtes, file_len)?;
		Ok((header, gtes, stats))
	}

	/// Reads `buf.len()` bytes starting `within` bytes into the data grain stored at sector `gte`.
	pub fn read_grain(&self, gte: u32, within: u64, buf: &mut [u8]) -> Result<()> {
		let grain_bytes = self.header.grain_size * SECTOR_SIZE;
		ensure!(gte as u64 >= self.header.overhead, "GTE {gte} does not point at a data grain");
		ensure!(within + buf.len() as u64 <= grain_bytes, "read of {} bytes at {within} crosses the grain boundary", buf.len());
		let offset = gte as u64 * SECTOR_SIZE + within;
		self.file.read_full_at(offset, buf).with_context(|| format!("reading grain data from {}", self.path.display()))
	}

	/// Reads raw grain data starting at `sector`; the range must lie after the metadata and inside the file.
	pub fn read_data(&self, sector: u64, buf: &mut [u8]) -> Result<()> {
		ensure!(sector >= self.header.overhead, "sector {sector} lies in the metadata area of {}", self.path.display());
		ensure!(
			sector * SECTOR_SIZE + buf.len() as u64 <= self.file_len,
			"read of {} bytes at sector {sector} extends past the end of {}",
			buf.len(),
			self.path.display()
		);
		self.file.read_full_at(sector * SECTOR_SIZE, buf).with_context(|| format!("reading grain data from {}", self.path.display()))
	}

	/// Reads raw bytes anywhere inside the file, metadata included.
	pub fn read_raw(&self, offset: u64, buf: &mut [u8]) -> Result<()> {
		ensure!(
			offset.checked_add(buf.len() as u64).is_some_and(|end| end <= self.file_len),
			"read of {} bytes at offset {offset} extends past the end of {}",
			buf.len(),
			self.path.display()
		);
		self.file.read_full_at(offset, buf).with_context(|| format!("reading {}", self.path.display()))
	}

	/// The whole metadata area `[0, overHead)`: header, grain directories, grain tables and padding.
	pub fn read_metadata(&self) -> Result<Vec<u8>> {
		let len = self.header.overhead * SECTOR_SIZE;
		ensure!(len <= self.file_len, "overHead ({len} bytes) extends past the end of {} ({} bytes)", self.path.display(), self.file_len);
		let mut v = vec![0u8; len as usize];
		self.read_raw(0, &mut v)?;
		Ok(v)
	}
}

#[cfg(test)]
mod tests {
	use super::*;

	/// Header bytes as found at offset 0 of `athenaxp-s001.vmdk`.
	fn real_header() -> Vec<u8> {
		let mut b = vec![0u8; HEADER_SIZE];
		let first: [u8; 80] = [
			0x4b, 0x44, 0x4d, 0x56, 0x01, 0x00, 0x00, 0x00, 0x03, 0x00, 0x00, 0x00, 0x00, 0x00, 0x7f, 0x00, //
			0x00, 0x00, 0x00, 0x00, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, //
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00, //
			0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xfe, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, //
			0x00, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x0a, 0x20, 0x0d, 0x0a, 0x00, 0x00, 0x00, //
		];
		b[..80].copy_from_slice(&first);
		b
	}

	#[test]
	fn parses_real_header() {
		let h = SparseHeader::parse(&real_header()).unwrap();
		assert_eq!(h.version, 1);
		assert_eq!(h.flags, 3);
		assert_eq!(h.capacity, 0x7f0000);
		assert_eq!(h.grain_size, 128);
		assert_eq!(h.descriptor_offset, 0);
		assert_eq!(h.descriptor_size, 0);
		assert_eq!(h.num_gtes_per_gt, 512);
		assert_eq!(h.rgd_offset, 1);
		assert_eq!(h.gd_offset, 0x1fe);
		assert_eq!(h.overhead, 0x400);
		assert_eq!(h.unclean_shutdown, 0);
		assert_eq!(&h.newline_chars, b"\n \r\n");
		assert_eq!(h.compress_algorithm, 0);
		h.validate().unwrap();
		assert_eq!(h.num_grains(), 65024);
		assert_eq!(h.num_gts(), 127);
		assert!(!h.zero_grain_supported());
	}

	#[test]
	fn rejects_bad_headers() {
		let mut b = real_header();
		b[0] = b'X';
		assert!(SparseHeader::parse(&b).is_err());
		assert!(SparseHeader::parse(&real_header()[..100]).is_err());

		let mut b = real_header();
		b[75] = b'\n'; // "\r" mangled by a text-mode copy
		assert!(SparseHeader::parse(&b).unwrap().validate().is_err());

		let mut b = real_header();
		b[10] = 0x01; // flags bit 16: compressed
		assert!(SparseHeader::parse(&b).unwrap().validate().is_err());

		let mut b = real_header();
		b[77] = 1; // compressAlgorithm deflate
		assert!(SparseHeader::parse(&b).unwrap().validate().is_err());

		let mut b = real_header();
		b[20] = 100; // grain size not a power of two
		assert!(SparseHeader::parse(&b).unwrap().validate().is_err());
	}

	/// Builds a small in-memory extent: capacity 1100 grains of 8 sectors (3 grain tables),
	/// layout rgd@1, rgts@2.., gd@20, gts@21.., overhead 40 sectors, grains after that.
	fn synthetic_extent(grains: &[(usize, u32)], redundant_differs: bool) -> Vec<u8> {
		let grain = 8u64;
		let capacity = 1100 * grain;
		let overhead = 40u64;
		let mut h = real_header();
		h[12..20].copy_from_slice(&capacity.to_le_bytes());
		h[20..28].copy_from_slice(&grain.to_le_bytes());
		h[48..56].copy_from_slice(&1u64.to_le_bytes());
		h[56..64].copy_from_slice(&20u64.to_le_bytes());
		h[64..72].copy_from_slice(&overhead.to_le_bytes());
		let data_grains = grains.iter().filter(|(_, s)| *s > 1).count() as u64;
		let mut f = vec![0u8; ((overhead + data_grains * grain) * SECTOR_SIZE) as usize];
		f[..HEADER_SIZE].copy_from_slice(&h);
		for (gd, gt0) in [(1u64, 2u64), (20, 21)] {
			for t in 0..3u64 {
				let gt = gt0 + t * 4;
				let o = (gd * SECTOR_SIZE + t * 4) as usize;
				f[o..o + 4].copy_from_slice(&(gt as u32).to_le_bytes());
			}
		}
		for &(g, sector) in grains {
			for (k, gt0) in [2u64, 21].into_iter().enumerate() {
				let mut v = sector;
				if redundant_differs && k == 0 {
					v = 0;
				}
				let o = (gt0 * SECTOR_SIZE) as usize + (g / 512) * 4 * SECTOR_SIZE as usize + (g % 512) * 4;
				f[o..o + 4].copy_from_slice(&v.to_le_bytes());
			}
		}
		f
	}

	#[test]
	fn loads_synthetic_tables() {
		let f = synthetic_extent(&[(0, 40), (513, 48), (1099, 56)], false);
		let (h, gtes, stats) = SparseExtent::load(&f, f.len() as u64).unwrap();
		assert_eq!(h.num_gts(), 3);
		assert_eq!(gtes.len(), 1100);
		assert_eq!(gtes[0], 40);
		assert_eq!(gtes[513], 48);
		assert_eq!(gtes[1099], 56);
		assert_eq!(gtes.iter().filter(|&&e| e != 0).count(), 3);
		assert_eq!(stats, GteStats { data_grains: 3, zero_grains: 0 });
	}

	#[test]
	fn rejects_inconsistent_tables() {
		// Redundant copy differs.
		let f = synthetic_extent(&[(0, 40)], true);
		assert!(SparseExtent::load(&f, f.len() as u64).is_err());
		// Grain inside the metadata area.
		let f = synthetic_extent(&[(0, 39)], false);
		assert!(SparseExtent::load(&f, f.len() as u64).is_err());
		// Overlapping grains.
		let f = synthetic_extent(&[(0, 40), (1, 44)], false);
		assert!(SparseExtent::load(&f, f.len() as u64).is_err());
		// Grain past the end of the file.
		let f = synthetic_extent(&[(0, 40)], false);
		assert!(SparseExtent::load(&f, f.len() as u64 - 1).is_err());
		// GTE 1 in a version 1 extent without the zero-grain flag.
		let f = synthetic_extent(&[(5, 1)], false);
		assert!(SparseExtent::load(&f, f.len() as u64).is_err());
		// Entry beyond capacity in the last grain table.
		let f = synthetic_extent(&[(1100, 40)], false);
		assert!(SparseExtent::load(&f, f.len() as u64).is_err());
	}

	#[test]
	fn accepts_zero_grains_when_flagged() {
		let mut f = synthetic_extent(&[(5, 1), (6, 40)], false);
		f[8] |= FLAG_ZERO_GRAIN_GTE as u8;
		let (_, gtes, stats) = SparseExtent::load(&f, f.len() as u64).unwrap();
		assert_eq!(gtes[5], GTE_ZERO_GRAIN);
		assert_eq!(stats, GteStats { data_grains: 1, zero_grains: 1 });
	}
}
