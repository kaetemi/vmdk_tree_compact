//! One layer of the snapshot tree: a descriptor plus its sparse extents, flattened into a
//! global grain index with an allocation bitset.

use crate::analysis::Bitset;
use crate::descriptor::Descriptor;
use crate::sparse::{SparseExtent, GTE_ZERO_GRAIN, SECTOR_SIZE};
use anyhow::{bail, ensure, Context, Result};
use std::path::Path;

pub struct LayerExtent {
	pub extent: SparseExtent,
	pub start_grain: u64,
	pub grains: u64,
}

pub struct Layer {
	/// Descriptor file name (relative to the VM directory).
	pub file_name: String,
	pub desc: Descriptor,
	pub extents: Vec<LayerExtent>,
	pub grain_sectors: u64,
	pub total_grains: u64,
	/// Grain table entry per global grain (0 = unallocated, 1 = zero grain where supported, else sector offset).
	gtes: Vec<u32>,
	/// Allocated = GTE != 0 (zero grains included: they mask the parent).
	pub alloc: Bitset,
	pub data_grains: u64,
	pub zero_gte_grains: u64,
	/// Sum of the extent file sizes.
	pub on_disk_bytes: u64,
	/// Sum of the per-extent metadata areas (overHead).
	pub overhead_bytes: u64,
}

pub const SUPPORTED_CREATE_TYPES: [&str; 2] = ["twoGbMaxExtentSparse", "monolithicSparse"];

impl Layer {
	pub fn open(dir: &Path, file_name: &str, desc: Descriptor) -> Result<Self> {
		Self::open_inner(dir, file_name, desc).with_context(|| format!("layer {file_name}"))
	}

	fn open_inner(dir: &Path, file_name: &str, desc: Descriptor) -> Result<Self> {
		ensure!(
			SUPPORTED_CREATE_TYPES.contains(&desc.create_type.as_str()),
			"createType {:?} is not supported (expected one of {:?})",
			desc.create_type,
			SUPPORTED_CREATE_TYPES
		);
		let mut extents = Vec::with_capacity(desc.extents.len());
		let mut grain_sectors = None;
		let mut start_grain = 0u64;
		for line in &desc.extents {
			ensure!(line.kind == "SPARSE", "extent type {:?} is not supported (only SPARSE)", line.kind);
			ensure!(line.access == "RW" || line.access == "RDONLY", "extent access {:?} is not supported", line.access);
			ensure!(line.offset.is_none(), "unexpected offset on sparse extent line");
			let name = line.file.as_deref().context("sparse extent line has no file name")?;
			ensure!(!name.contains('/') && !name.contains('\\'), "extent {name:?} is outside the VM directory; not supported");
			let extent = SparseExtent::open(&dir.join(name))?;
			let gs = extent.header.grain_size;
			match grain_sectors {
				None => grain_sectors = Some(gs),
				Some(prev) => ensure!(prev == gs, "extent {name} has grain size {gs}, previous extents {prev}"),
			}
			ensure!(line.sectors % gs == 0, "extent {name} size {} sectors is not a multiple of the grain size {gs}", line.sectors);
			ensure!(
				extent.header.capacity == line.sectors,
				"extent {name} header capacity {} differs from descriptor size {}",
				extent.header.capacity,
				line.sectors
			);
			let grains = line.sectors / gs;
			ensure!(extent.gtes.len() as u64 == grains, "extent {name} grain table covers {} grains, expected {grains}", extent.gtes.len());
			extents.push(LayerExtent { extent, start_grain, grains });
			start_grain += grains;
		}
		let grain_sectors = grain_sectors.context("no extents")?;
		let total_grains = start_grain;
		let mut gtes = Vec::with_capacity(total_grains as usize);
		let mut alloc = Bitset::new(total_grains as usize);
		let (mut data_grains, mut zero_gte_grains, mut on_disk_bytes, mut overhead_bytes) = (0, 0, 0, 0);
		for le in &mut extents {
			// Move the tables into the flat per-layer index; the extent keeps only its header and file.
			gtes.append(&mut le.extent.gtes);
			data_grains += le.extent.stats.data_grains;
			zero_gte_grains += le.extent.stats.zero_grains;
			on_disk_bytes += le.extent.file_len;
			overhead_bytes += le.extent.header.overhead * SECTOR_SIZE;
		}
		for (g, &e) in gtes.iter().enumerate() {
			if e != 0 {
				alloc.set(g);
			}
		}
		ensure!(alloc.count() == data_grains + zero_gte_grains, "allocation count mismatch");
		ensure!(
			data_grains * grain_sectors * SECTOR_SIZE + overhead_bytes <= on_disk_bytes,
			"allocated grains plus metadata ({} bytes) exceed the extent file sizes ({on_disk_bytes} bytes)",
			data_grains * grain_sectors * SECTOR_SIZE + overhead_bytes
		);
		Ok(Self {
			file_name: file_name.to_string(),
			desc,
			extents,
			grain_sectors,
			total_grains,
			gtes,
			alloc,
			data_grains,
			zero_gte_grains,
			on_disk_bytes,
			overhead_bytes,
		})
	}

	pub fn grain_bytes(&self) -> u64 {
		self.grain_sectors * SECTOR_SIZE
	}

	pub fn capacity_sectors(&self) -> u64 {
		self.total_grains * self.grain_sectors
	}

	pub fn allocated_grains(&self) -> u64 {
		self.data_grains + self.zero_gte_grains
	}

	pub fn gte(&self, g: u64) -> u32 {
		self.gtes[g as usize]
	}

	/// True if grain `g` is allocated as a zero grain (reads as zeros, masks the parent).
	pub fn is_zero_grain(&self, g: u64) -> bool {
		self.gte(g) == GTE_ZERO_GRAIN && self.extent_of(g).extent.header.zero_grain_supported()
	}

	pub fn extent_of(&self, g: u64) -> &LayerExtent {
		let i = self.extents.partition_point(|e| e.start_grain + e.grains <= g);
		&self.extents[i]
	}

	/// Reads part of grain `g`, which must be allocated in this layer.
	pub fn read_grain(&self, g: u64, within: u64, buf: &mut [u8]) -> Result<()> {
		let e = self.gte(g);
		if e == 0 {
			bail!("grain {g} is not allocated in {}", self.file_name);
		}
		if self.is_zero_grain(g) {
			buf.fill(0);
			return Ok(());
		}
		self.extent_of(g).extent.read_grain(e, within, buf)
	}

	/// Data grains of this layer as (global grain, extent index, sector offset), for bulk scans.
	pub fn data_grain_locations(&self) -> Vec<(u64, usize, u32)> {
		let mut v = Vec::with_capacity(self.data_grains as usize);
		for (xi, le) in self.extents.iter().enumerate() {
			for g in le.start_grain..le.start_grain + le.grains {
				let e = self.gte(g);
				if e != 0 && !self.is_zero_grain(g) {
					v.push((g, xi, e));
				}
			}
		}
		v
	}
}
