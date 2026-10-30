//! Grain bitsets and the reclaim analysis.
//!
//! A grain in layer L is reclaimable iff, at every node N in the subtree rooted at L (L included)
//! where the grain is still visible (no layer on the path L -> N below L allocates it), the NTFS
//! `$Bitmap` as seen at N marks every cluster covering the grain as free.

use crate::layer::Layer;
use crate::sparse::SECTOR_SIZE;
use anyhow::{ensure, Result};

/// The algorithm from DESIGN.md: for each layer L, walk its subtree carrying the set of grains
/// masked by layers below L; L must keep every grain still visible at a node where it is not free.
pub fn reclaimable(children: &[Vec<usize>], alloc: &[Bitset], free: &[Bitset]) -> Vec<Bitset> {
	(0..alloc.len())
		.map(|l| {
			let len = alloc[l].len();
			let mut keep = Bitset::new(len);
			let mut stack = vec![(l, Bitset::new(len))];
			while let Some((node, masked)) = stack.pop() {
				let mut needed = alloc[l].clone();
				needed.and_not_assign(&masked);
				if needed.is_empty() {
					// Nothing of L is visible here or anywhere below.
					continue;
				}
				needed.and_not_assign(&free[node]);
				keep.or_assign(&needed);
				for &c in &children[node] {
					let mut m = masked.clone();
					m.or_assign(&alloc[c]);
					stack.push((c, m));
				}
			}
			let mut r = alloc[l].clone();
			r.and_not_assign(&keep);
			r
		})
		.collect()
}

fn path_to_root(parent: &[Option<usize>], n: usize) -> Vec<usize> {
	let mut path = vec![n];
	let mut cur = n;
	while let Some(p) = parent[cur] {
		assert!(path.len() <= parent.len(), "parent cycle");
		path.push(p);
		cur = p;
	}
	path
}

/// Layer serving grain `g` when reading along `path` (node first, base last).
fn provider(path: &[usize], alloc: &[Bitset], g: usize) -> Option<usize> {
	path.iter().copied().find(|&l| alloc[l].get(g))
}

/// Independent formulation used as a cross-check: for every node and every grain that is not
/// free there, the layer serving that grain at that node must keep it.
pub fn reclaimable_by_provider(parent: &[Option<usize>], alloc: &[Bitset], free: &[Bitset]) -> Vec<Bitset> {
	let len = alloc.first().map_or(0, |a| a.len());
	let mut keep: Vec<Bitset> = alloc.iter().map(|_| Bitset::new(len)).collect();
	for node in 0..alloc.len() {
		let path = path_to_root(parent, node);
		for g in 0..len {
			if free[node].get(g) {
				continue;
			}
			if let Some(l) = provider(&path, alloc, g) {
				keep[l].set(g);
			}
		}
	}
	alloc
		.iter()
		.zip(&keep)
		.map(|(a, k)| {
			let mut r = a.clone();
			r.and_not_assign(k);
			r
		})
		.collect()
}

/// Simulates dropping all reclaimable grains at once and checks that every node still reads every
/// grain it does not consider free from the same layer as before (so its content is unchanged).
pub fn verify_reclaim(parent: &[Option<usize>], alloc: &[Bitset], free: &[Bitset], reclaim: &[Bitset]) -> Result<()> {
	let len = alloc.first().map_or(0, |a| a.len());
	let mut after = Vec::with_capacity(alloc.len());
	for (l, (a, r)) in alloc.iter().zip(reclaim).enumerate() {
		ensure!(r.is_subset_of(a), "layer {l}: reclaimable grains are not a subset of the allocated grains");
		let mut x = a.clone();
		x.and_not_assign(r);
		after.push(x);
	}
	for node in 0..alloc.len() {
		let path = path_to_root(parent, node);
		for g in 0..len {
			if free[node].get(g) {
				continue;
			}
			let (before, now) = (provider(&path, alloc, g), provider(&path, &after, g));
			ensure!(before == now, "node {node}: in-use grain {g} would be served by layer {now:?} instead of {before:?} after reclaiming");
		}
	}
	Ok(())
}

/// Runs the DESIGN.md algorithm, cross-checks it against the provider formulation and the
/// simulated removal, and returns the reclaimable grains per layer.
pub fn analyze(parent: &[Option<usize>], children: &[Vec<usize>], alloc: &[Bitset], free: &[Bitset]) -> Result<Vec<Bitset>> {
	ensure!(parent.len() == alloc.len() && children.len() == alloc.len() && free.len() == alloc.len(), "inconsistent tree sizes");
	let r = reclaimable(children, alloc, free);
	let check = reclaimable_by_provider(parent, alloc, free);
	if let Some(l) = (0..r.len()).find(|&l| r[l] != check[l]) {
		anyhow::bail!("reclaim computations disagree for layer {l} ({} vs {} grains); refusing to report", r[l].count(), check[l].count());
	}
	verify_reclaim(parent, alloc, free, &r)?;
	Ok(r)
}

/// Reads every data grain of the layer and returns the set of grains whose content is all zero.
/// Grains are read in file order, contiguous runs in batches. `progress` gets the bytes read so far.
pub fn scan_zero(layer: &Layer, progress: &mut dyn FnMut(u64)) -> Result<Bitset> {
	const BATCH: u64 = 16 << 20;
	let gb = layer.grain_bytes();
	let gs = layer.grain_sectors;
	let mut zero = Bitset::new(layer.total_grains as usize);
	let mut locs = layer.data_grain_locations();
	locs.sort_unstable_by_key(|&(_, x, s)| (x, s));
	let mut buf = vec![0u8; BATCH as usize];
	let mut done = 0u64;
	let mut i = 0;
	while i < locs.len() {
		let (_, x, s0) = locs[i];
		let mut j = i + 1;
		while j < locs.len() && locs[j].1 == x && locs[j].2 as u64 == s0 as u64 + (j - i) as u64 * gs && (j - i + 1) as u64 * gb <= BATCH {
			j += 1;
		}
		let bytes = ((j - i) as u64 * gb) as usize;
		layer.extents[x].extent.read_data(s0 as u64, &mut buf[..bytes])?;
		for (k, chunk) in buf[..bytes].chunks_exact(gb as usize).enumerate() {
			if chunk.chunks(256).all(|c| c.iter().fold(0u8, |a, &b| a | b) == 0) {
				zero.set(locs[i + k].0 as usize);
			}
		}
		done += bytes as u64;
		progress(done);
		i = j;
	}
	debug_assert_eq!(done, layer.data_grains * gs * SECTOR_SIZE);
	Ok(zero)
}

/// Fixed-size bitset over grain indices.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Bitset {
	words: Vec<u64>,
	len: usize,
}

impl Bitset {
	pub fn new(len: usize) -> Self {
		Self { words: vec![0; len.div_ceil(64)], len }
	}

	pub fn len(&self) -> usize {
		self.len
	}

	pub fn get(&self, i: usize) -> bool {
		assert!(i < self.len, "bit {i} out of range {}", self.len);
		(self.words[i >> 6] >> (i & 63)) & 1 != 0
	}

	pub fn set(&mut self, i: usize) {
		assert!(i < self.len, "bit {i} out of range {}", self.len);
		self.words[i >> 6] |= 1 << (i & 63);
	}

	pub fn count(&self) -> u64 {
		self.words.iter().map(|w| w.count_ones() as u64).sum()
	}

	pub fn is_empty(&self) -> bool {
		self.words.iter().all(|&w| w == 0)
	}

	pub fn or_assign(&mut self, o: &Bitset) {
		assert_eq!(self.len, o.len);
		self.words.iter_mut().zip(&o.words).for_each(|(a, b)| *a |= b);
	}

	pub fn and_not_assign(&mut self, o: &Bitset) {
		assert_eq!(self.len, o.len);
		self.words.iter_mut().zip(&o.words).for_each(|(a, b)| *a &= !b);
	}

	pub fn is_subset_of(&self, o: &Bitset) -> bool {
		assert_eq!(self.len, o.len);
		self.words.iter().zip(&o.words).all(|(a, b)| a & !b == 0)
	}

	/// Bits `[start, start + len)` as a new bitset indexed from 0.
	pub fn slice(&self, start: usize, len: usize) -> Bitset {
		assert!(start + len <= self.len, "slice {start}+{len} out of range {}", self.len);
		let mut b = Bitset::new(len);
		(0..len).filter(|&i| self.get(start + i)).for_each(|i| b.set(i));
		b
	}

	pub fn iter_ones(&self) -> impl Iterator<Item = usize> + '_ {
		self.words.iter().enumerate().flat_map(|(wi, &w)| {
			let mut w = w;
			std::iter::from_fn(move || {
				if w == 0 {
					return None;
				}
				let b = w.trailing_zeros() as usize;
				w &= w - 1;
				Some(wi * 64 + b)
			})
		})
	}
}

#[cfg(test)]
mod tests {
	use super::*;

	fn bits(len: usize, ones: &[usize]) -> Bitset {
		let mut b = Bitset::new(len);
		ones.iter().for_each(|&i| b.set(i));
		b
	}

	fn ones(b: &Bitset) -> Vec<usize> {
		b.iter_ones().collect()
	}

	/// Base layer 0 with two child layers 1 and 2 (a branch), 8 grains.
	#[test]
	fn reclaim_on_branched_three_layer_tree() {
		let parent = vec![None, Some(0), Some(0)];
		let children = vec![vec![1, 2], vec![], vec![]];
		let alloc = vec![bits(8, &[0, 1, 2, 3, 4, 5]), bits(8, &[1, 6]), bits(8, &[2, 7])];
		let free = vec![bits(8, &[0, 1, 3]), bits(8, &[0, 2, 3, 6]), bits(8, &[0, 1, 3, 4, 7])];
		let r = analyze(&parent, &children, &alloc, &free).unwrap();
		// Layer 0: grain 0 and 3 free everywhere; grain 1 is visible only at nodes 0 and 2 (layer 1
		// masks it at node 1) and free at both; grain 2 is visible at nodes 0 and 1 but in use at 0;
		// grain 4 in use at node 0; grain 5 in use everywhere.
		assert_eq!(ones(&r[0]), vec![0, 1, 3]);
		// Leaves: only their own free grains.
		assert_eq!(ones(&r[1]), vec![6]);
		assert_eq!(ones(&r[2]), vec![7]);

		// Claiming grain 2 of the base as reclaimable would change what node 0 reads.
		let mut wrong = r.clone();
		wrong[0].set(2);
		assert!(verify_reclaim(&parent, &alloc, &free, &wrong).is_err());
		// Grain 1 of layer 1 is in use at node 1.
		let mut wrong = r.clone();
		wrong[1].set(1);
		assert!(verify_reclaim(&parent, &alloc, &free, &wrong).is_err());
	}

	/// Chain 0 -> 1 -> 2.
	#[test]
	fn reclaim_on_three_layer_chain() {
		let parent = vec![None, Some(0), Some(1)];
		let children = vec![vec![1], vec![2], vec![]];
		let alloc = vec![bits(6, &[0, 1, 2, 3]), bits(6, &[1, 2]), bits(6, &[2, 4])];
		let free = vec![bits(6, &[0, 1, 3]), bits(6, &[0, 2, 3]), bits(6, &[0, 1, 4])];
		let r = analyze(&parent, &children, &alloc, &free).unwrap();
		// Layer 0: grain 1 is masked below and free at node 0; grain 3 is in use at node 2.
		assert_eq!(ones(&r[0]), vec![0, 1]);
		// Layer 1: grain 1 in use at node 1; grain 2 masked at node 2 and free at node 1.
		assert_eq!(ones(&r[1]), vec![2]);
		assert_eq!(ones(&r[2]), vec![4]);
	}

	/// Random trees: the DESIGN.md algorithm and the provider formulation must always agree.
	#[test]
	fn reclaim_matches_provider_formulation_on_random_trees() {
		let mut seed = 0x2545_f491_4f6c_dd1du64;
		let mut rnd = move |m: u64| {
			seed ^= seed << 13;
			seed ^= seed >> 7;
			seed ^= seed << 17;
			seed % m
		};
		for _ in 0..200 {
			let n = 1 + rnd(8) as usize;
			let len = 1 + rnd(150) as usize;
			let parent: Vec<Option<usize>> = (0..n).map(|i| if i == 0 { None } else { Some(rnd(i as u64) as usize) }).collect();
			let mut children = vec![Vec::new(); n];
			for i in 1..n {
				children[parent[i].unwrap()].push(i);
			}
			let mk = |rnd: &mut dyn FnMut(u64) -> u64, pct: u64| {
				let mut b = Bitset::new(len);
				(0..len).filter(|_| rnd(100) < pct).for_each(|g| b.set(g));
				b
			};
			let alloc: Vec<Bitset> = (0..n).map(|_| mk(&mut rnd, 40)).collect();
			let free: Vec<Bitset> = (0..n).map(|_| mk(&mut rnd, 70)).collect();
			let r = analyze(&parent, &children, &alloc, &free).unwrap();
			for l in 0..n {
				assert!(r[l].is_subset_of(&alloc[l]));
				// A reclaimable grain of a layer must be free at that layer's own node.
				assert!(r[l].is_subset_of(&free[l]));
			}
		}
	}

	#[test]
	fn bitset_basics() {
		let mut a = Bitset::new(130);
		assert!(a.is_empty());
		a.set(0);
		a.set(64);
		a.set(129);
		assert_eq!(a.count(), 3);
		assert!(a.get(64) && !a.get(63));
		assert_eq!(a.iter_ones().collect::<Vec<_>>(), vec![0, 64, 129]);
		let mut b = Bitset::new(130);
		b.set(64);
		assert!(b.is_subset_of(&a) && !a.is_subset_of(&b));
		let mut c = a.clone();
		c.and_not_assign(&b);
		assert_eq!(c.iter_ones().collect::<Vec<_>>(), vec![0, 129]);
		c.or_assign(&b);
		assert_eq!(c, a);
		c.and_not_assign(&a);
		assert!(c.is_empty());
	}
}
