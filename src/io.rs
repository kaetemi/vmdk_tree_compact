//! Positioned, read-only file access and little-endian field helpers.

use anyhow::{bail, ensure, Context, Result};
use std::fs::File;

/// Positioned reads that fill the whole buffer or fail.
pub trait ReadAt {
	fn read_full_at(&self, offset: u64, buf: &mut [u8]) -> Result<()>;
}

impl ReadAt for File {
	#[cfg(windows)]
	fn read_full_at(&self, offset: u64, buf: &mut [u8]) -> Result<()> {
		use std::os::windows::fs::FileExt;
		let mut pos = 0usize;
		while pos < buf.len() {
			let at = offset + pos as u64;
			let n = self.seek_read(&mut buf[pos..], at).with_context(|| format!("reading {} bytes at offset {}", buf.len() - pos, at))?;
			if n == 0 {
				bail!("unexpected end of file reading {} bytes at offset {}", buf.len() - pos, at);
			}
			pos += n;
		}
		Ok(())
	}

	#[cfg(unix)]
	fn read_full_at(&self, offset: u64, buf: &mut [u8]) -> Result<()> {
		use std::os::unix::fs::FileExt;
		FileExt::read_exact_at(self, buf, offset).with_context(|| format!("reading {} bytes at offset {}", buf.len(), offset))
	}
}

impl ReadAt for Vec<u8> {
	fn read_full_at(&self, offset: u64, buf: &mut [u8]) -> Result<()> {
		let start = usize::try_from(offset)?;
		let end = start.checked_add(buf.len()).context("read range overflows")?;
		ensure!(end <= self.len(), "read of {} bytes at offset {} past end of {}-byte buffer", buf.len(), offset, self.len());
		buf.copy_from_slice(&self[start..end]);
		Ok(())
	}
}

/// Opens a file strictly for reading. Never creates or truncates.
pub fn open_read_only(path: &std::path::Path) -> Result<File> {
	std::fs::OpenOptions::new().read(true).open(path).with_context(|| format!("opening {} read-only", path.display()))
}

pub fn le16(b: &[u8], o: usize) -> u16 {
	u16::from_le_bytes(b[o..o + 2].try_into().unwrap())
}

pub fn le32(b: &[u8], o: usize) -> u32 {
	u32::from_le_bytes(b[o..o + 4].try_into().unwrap())
}

pub fn le64(b: &[u8], o: usize) -> u64 {
	u64::from_le_bytes(b[o..o + 8].try_into().unwrap())
}
