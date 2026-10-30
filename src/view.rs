//! Chain-view reader: the virtual disk as seen at one node of the snapshot tree.
//! Each grain is served by the nearest layer on the path node -> base that allocates it;
//! grains no layer allocates read as zeros.

use crate::tree::Tree;
use anyhow::{ensure, Result};

/// A readable virtual disk of fixed size.
pub trait Disk {
	fn size(&self) -> u64;
	fn read_at(&self, offset: u64, buf: &mut [u8]) -> Result<()>;
}

pub struct ChainView<'a> {
	tree: &'a Tree,
	/// Node indices from the viewed node up to the base disk.
	path: Vec<usize>,
	grain_bytes: u64,
}

impl<'a> ChainView<'a> {
	pub fn new(tree: &'a Tree, node: usize) -> Self {
		Self { tree, path: tree.path_to_root(node), grain_bytes: tree.grain_bytes() }
	}

	/// The node whose layer serves grain `g` at this view, if any.
	pub fn provider(&self, g: u64) -> Option<usize> {
		self.path.iter().copied().find(|&n| self.tree.nodes[n].layer.alloc.get(g as usize))
	}
}

impl Disk for ChainView<'_> {
	fn size(&self) -> u64 {
		self.tree.capacity_bytes()
	}

	fn read_at(&self, offset: u64, buf: &mut [u8]) -> Result<()> {
		ensure!(
			offset.checked_add(buf.len() as u64).is_some_and(|end| end <= self.size()),
			"read of {} bytes at offset {offset} lies beyond the end of the {}-byte virtual disk",
			buf.len(),
			self.size()
		);
		let gb = self.grain_bytes;
		let mut pos = 0usize;
		while pos < buf.len() {
			let abs = offset + pos as u64;
			let (g, within) = (abs / gb, abs % gb);
			let n = ((gb - within) as usize).min(buf.len() - pos);
			let chunk = &mut buf[pos..pos + n];
			match self.provider(g) {
				None => chunk.fill(0),
				Some(node) => self.tree.nodes[node].layer.read_grain(g, within, chunk)?,
			}
			pos += n;
		}
		Ok(())
	}
}

/// In-memory disk for tests.
#[cfg(test)]
pub struct MemDisk(pub Vec<u8>);

#[cfg(test)]
impl Disk for MemDisk {
	fn size(&self) -> u64 {
		self.0.len() as u64
	}

	fn read_at(&self, offset: u64, buf: &mut [u8]) -> Result<()> {
		use crate::io::ReadAt;
		self.0.read_full_at(offset, buf)
	}
}
