//! Partition scanning: MBR (primary and extended/logical) and GPT (behind a protective MBR).

use crate::io::{le32, le64};
use crate::view::Disk;
use anyhow::{bail, ensure, Context, Result};
use std::collections::HashSet;

/// Partition tables address 512-byte sectors (VMDK sectors are always 512 bytes).
pub const LBA_SIZE: u64 = 512;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Scheme {
	/// No partition table signature: nothing on the disk is treated as free.
	None,
	Mbr,
	Gpt,
	/// An NTFS boot sector at LBA 0 (volume without a partition table).
	Superfloppy,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Partition {
	pub number: u32,
	pub kind: String,
	pub start_lba: u64,
	pub sectors: u64,
}

impl Partition {
	pub fn offset(&self) -> u64 {
		self.start_lba * LBA_SIZE
	}

	pub fn size(&self) -> u64 {
		self.sectors * LBA_SIZE
	}
}

#[derive(Debug, Clone)]
pub struct PartitionTable {
	pub scheme: Scheme,
	pub partitions: Vec<Partition>,
}

#[derive(Debug, Clone, Copy)]
struct MbrEntry {
	status: u8,
	ptype: u8,
	start: u64,
	sectors: u64,
}

fn mbr_entries(s: &[u8]) -> [MbrEntry; 4] {
	std::array::from_fn(|i| {
		let o = 446 + 16 * i;
		MbrEntry { status: s[o], ptype: s[o + 4], start: le32(s, o + 8) as u64, sectors: le32(s, o + 12) as u64 }
	})
}

fn is_extended(t: u8) -> bool {
	matches!(t, 0x05 | 0x0f | 0x85)
}

fn has_signature(s: &[u8]) -> bool {
	s[510] == 0x55 && s[511] == 0xaa
}

pub fn scan(disk: &dyn Disk) -> Result<PartitionTable> {
	let total = disk.size() / LBA_SIZE;
	let mut s0 = [0u8; 512];
	disk.read_at(0, &mut s0)?;
	if !has_signature(&s0) {
		return Ok(PartitionTable { scheme: Scheme::None, partitions: Vec::new() });
	}
	if &s0[3..11] == crate::ntfs::OEM_NTFS {
		return Ok(PartitionTable {
			scheme: Scheme::Superfloppy,
			partitions: vec![Partition { number: 0, kind: "whole disk".into(), start_lba: 0, sectors: total }],
		});
	}
	let entries = mbr_entries(&s0);
	if entries.iter().any(|e| e.ptype == 0xee) {
		return scan_gpt(disk, total);
	}
	let mut parts = Vec::new();
	let mut next_logical = 5u32;
	let mut extended_seen = false;
	for (i, e) in entries.iter().enumerate() {
		if e.ptype == 0 {
			continue;
		}
		ensure!(e.status == 0 || e.status == 0x80, "MBR entry {}: invalid status byte {:#04x}", i + 1, e.status);
		ensure!(
			e.start > 0 && e.sectors > 0 && e.start + e.sectors <= total,
			"MBR entry {}: range {}+{} lies outside the {total}-sector disk",
			i + 1,
			e.start,
			e.sectors
		);
		if is_extended(e.ptype) {
			ensure!(!extended_seen, "MBR has more than one extended partition");
			extended_seen = true;
			walk_ebr(disk, e.start, e.sectors, &mut parts, &mut next_logical).with_context(|| format!("extended partition in MBR entry {}", i + 1))?;
		} else {
			parts.push(Partition { number: i as u32 + 1, kind: format!("MBR type {:#04x}", e.ptype), start_lba: e.start, sectors: e.sectors });
		}
	}
	check_overlaps(&mut parts)?;
	Ok(PartitionTable { scheme: Scheme::Mbr, partitions: parts })
}

fn walk_ebr(disk: &dyn Disk, ext_start: u64, ext_sectors: u64, parts: &mut Vec<Partition>, next: &mut u32) -> Result<()> {
	let ext_end = ext_start + ext_sectors;
	let mut ebr = ext_start;
	let mut seen = HashSet::new();
	loop {
		ensure!(seen.insert(ebr), "EBR chain loops at LBA {ebr}");
		ensure!(seen.len() <= 256, "EBR chain is implausibly long");
		let mut s = [0u8; 512];
		disk.read_at(ebr * LBA_SIZE, &mut s)?;
		ensure!(has_signature(&s), "EBR at LBA {ebr} has no 55aa signature");
		let e = mbr_entries(&s);
		ensure!(e[2].ptype == 0 && e[3].ptype == 0, "EBR at LBA {ebr} uses entries 3/4");
		if e[0].ptype != 0 {
			ensure!(!is_extended(e[0].ptype), "EBR at LBA {ebr}: first entry is an extended link");
			let start = ebr + e[0].start;
			ensure!(
				e[0].start > 0 && e[0].sectors > 0 && start + e[0].sectors <= ext_end,
				"logical partition at LBA {start} lies outside the extended partition"
			);
			parts.push(Partition { number: *next, kind: format!("MBR logical type {:#04x}", e[0].ptype), start_lba: start, sectors: e[0].sectors });
			*next += 1;
		}
		if e[1].ptype == 0 {
			return Ok(());
		}
		ensure!(is_extended(e[1].ptype), "EBR at LBA {ebr}: second entry has type {:#04x}, expected an extended link", e[1].ptype);
		ebr = ext_start + e[1].start;
		ensure!(ebr > ext_start && ebr < ext_end, "EBR link to LBA {ebr} lies outside the extended partition");
	}
}

fn check_overlaps(parts: &mut [Partition]) -> Result<()> {
	parts.sort_by_key(|p| p.start_lba);
	for w in parts.windows(2) {
		ensure!(w[0].start_lba + w[0].sectors <= w[1].start_lba, "partitions {} and {} overlap", w[0].number, w[1].number);
	}
	Ok(())
}

pub fn crc32(data: &[u8]) -> u32 {
	let mut crc = 0xffff_ffffu32;
	for &b in data {
		crc ^= b as u32;
		for _ in 0..8 {
			crc = if crc & 1 != 0 { (crc >> 1) ^ 0xedb8_8320 } else { crc >> 1 };
		}
	}
	!crc
}

fn guid(b: &[u8]) -> String {
	format!(
		"{:08X}-{:04X}-{:04X}-{:02X}{:02X}-{}",
		le32(b, 0),
		u16::from_le_bytes([b[4], b[5]]),
		u16::from_le_bytes([b[6], b[7]]),
		b[8],
		b[9],
		b[10..16].iter().map(|x| format!("{x:02X}")).collect::<String>()
	)
}

fn scan_gpt(disk: &dyn Disk, total: u64) -> Result<PartitionTable> {
	let mut h = [0u8; 512];
	disk.read_at(LBA_SIZE, &mut h)?;
	ensure!(&h[0..8] == b"EFI PART", "protective MBR present but no GPT header at LBA 1");
	let hsize = le32(&h, 12) as usize;
	ensure!((92..=512).contains(&hsize), "GPT header size {hsize} is invalid");
	let mut hc = h[..hsize].to_vec();
	hc[16..20].fill(0);
	ensure!(crc32(&hc) == le32(&h, 16), "GPT header CRC mismatch");
	ensure!(le64(&h, 24) == 1, "GPT header at LBA 1 claims to be at LBA {}", le64(&h, 24));
	let (first_usable, last_usable) = (le64(&h, 40), le64(&h, 48));
	ensure!(first_usable <= last_usable && last_usable < total, "GPT usable range {first_usable}..{last_usable} is invalid for a {total}-sector disk");
	let entries_lba = le64(&h, 72);
	let (num, esize) = (le32(&h, 80) as usize, le32(&h, 84) as usize);
	ensure!(esize >= 128 && esize % 8 == 0 && num <= 4096, "GPT entry array ({num} x {esize} bytes) is invalid");
	let mut buf = vec![0u8; num * esize];
	disk.read_at(entries_lba * LBA_SIZE, &mut buf)?;
	ensure!(crc32(&buf) == le32(&h, 88), "GPT partition entry array CRC mismatch");
	let mut parts = Vec::new();
	for i in 0..num {
		let e = &buf[i * esize..(i + 1) * esize];
		if e[0..16].iter().all(|&b| b == 0) {
			continue;
		}
		let (first, last) = (le64(e, 32), le64(e, 40));
		ensure!(first <= last && first >= first_usable && last <= last_usable, "GPT entry {}: range {first}..{last} is outside the usable area", i + 1);
		parts.push(Partition { number: i as u32 + 1, kind: format!("GPT {}", guid(&e[0..16])), start_lba: first, sectors: last - first + 1 });
	}
	if parts.is_empty() {
		bail!("GPT has no partitions");
	}
	check_overlaps(&mut parts)?;
	Ok(PartitionTable { scheme: Scheme::Gpt, partitions: parts })
}

#[cfg(test)]
mod tests {
	use super::*;
	use crate::view::MemDisk;

	fn put_entry(s: &mut [u8], slot: usize, ptype: u8, start: u32, sectors: u32) {
		let o = 446 + 16 * slot;
		s[o + 4] = ptype;
		s[o + 8..o + 12].copy_from_slice(&start.to_le_bytes());
		s[o + 12..o + 16].copy_from_slice(&sectors.to_le_bytes());
	}

	#[test]
	fn crc32_matches_reference() {
		assert_eq!(crc32(b"123456789"), 0xcbf4_3926);
	}

	#[test]
	fn scans_mbr_with_logical_partitions() {
		let mut d = vec![0u8; 4096 * 512];
		d[510] = 0x55;
		d[511] = 0xaa;
		put_entry(&mut d, 0, 0x07, 63, 1000);
		put_entry(&mut d, 1, 0x0f, 2048, 2048);
		// EBR 1 at 2048: logical at +63, link to EBR 2 at ext+1024.
		let e1 = 2048 * 512;
		d[e1 + 510] = 0x55;
		d[e1 + 511] = 0xaa;
		put_entry(&mut d[e1..], 0, 0x07, 63, 900);
		put_entry(&mut d[e1..], 1, 0x05, 1024, 1024);
		let e2 = (2048 + 1024) * 512;
		d[e2 + 510] = 0x55;
		d[e2 + 511] = 0xaa;
		put_entry(&mut d[e2..], 0, 0x0b, 63, 961);
		let t = scan(&MemDisk(d)).unwrap();
		assert_eq!(t.scheme, Scheme::Mbr);
		let got: Vec<(u32, u64, u64)> = t.partitions.iter().map(|p| (p.number, p.start_lba, p.sectors)).collect();
		assert_eq!(got, vec![(1, 63, 1000), (5, 2111, 900), (6, 3135, 961)]);
	}

	#[test]
	fn rejects_overlapping_mbr_partitions() {
		let mut d = vec![0u8; 4096 * 512];
		d[510] = 0x55;
		d[511] = 0xaa;
		put_entry(&mut d, 0, 0x07, 63, 1000);
		put_entry(&mut d, 1, 0x07, 1000, 100);
		assert!(scan(&MemDisk(d)).is_err());
	}
}
