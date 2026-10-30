//! Grain bitsets and the reclaim analysis.

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

	pub fn and_assign(&mut self, o: &Bitset) {
		assert_eq!(self.len, o.len);
		self.words.iter_mut().zip(&o.words).for_each(|(a, b)| *a &= b);
	}

	pub fn and_not_assign(&mut self, o: &Bitset) {
		assert_eq!(self.len, o.len);
		self.words.iter_mut().zip(&o.words).for_each(|(a, b)| *a &= !b);
	}

	pub fn is_subset_of(&self, o: &Bitset) -> bool {
		assert_eq!(self.len, o.len);
		self.words.iter().zip(&o.words).all(|(a, b)| a & !b == 0)
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
		c.and_assign(&b);
		assert_eq!(c, b);
	}
}
