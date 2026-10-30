//! VMDK text descriptor parser (`CID`, `parentCID`, `createType`, `parentFileNameHint`, extent lines).

use anyhow::{bail, ensure, Context, Result};

/// `parentCID` value meaning "this disk has no parent".
pub const NO_PARENT: u32 = 0xffff_ffff;

/// One `RW <sectors> SPARSE "<file>"` style extent description line.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExtentLine {
	pub access: String,
	pub sectors: u64,
	pub kind: String,
	pub file: Option<String>,
	pub offset: Option<u64>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Descriptor {
	pub cid: u32,
	pub parent_cid: u32,
	pub create_type: String,
	pub parent_hint: Option<String>,
	pub extents: Vec<ExtentLine>,
}

impl Descriptor {
	pub fn parse(text: &str) -> Result<Self> {
		let mut cid = None;
		let mut parent_cid = None;
		let mut create_type = None;
		let mut parent_hint = None;
		let mut extents = Vec::new();
		for (i, raw) in text.lines().enumerate() {
			let lineno = i + 1;
			let line = raw.trim();
			if line.is_empty() || line.starts_with('#') {
				continue;
			}
			if let Some(ext) = parse_extent_line(line).with_context(|| format!("descriptor line {lineno}: {line:?}"))? {
				extents.push(ext);
				continue;
			}
			let Some((key, value)) = line.split_once('=') else {
				bail!("descriptor line {lineno}: unrecognised line {line:?}");
			};
			let key = key.trim();
			let value = unquote(value.trim());
			let ctx = || format!("descriptor line {lineno}: {line:?}");
			match key {
				"CID" => set_once(&mut cid, parse_cid(value).with_context(ctx)?, key).with_context(ctx)?,
				"parentCID" => set_once(&mut parent_cid, parse_cid(value).with_context(ctx)?, key).with_context(ctx)?,
				"createType" => set_once(&mut create_type, value.to_string(), key).with_context(ctx)?,
				"parentFileNameHint" => set_once(&mut parent_hint, value.to_string(), key).with_context(ctx)?,
				// version, encoding, ddb.* and anything else are not needed here.
				_ => {}
			}
		}
		let cid = cid.context("descriptor has no CID")?;
		let parent_cid = parent_cid.context("descriptor has no parentCID")?;
		let create_type = create_type.context("descriptor has no createType")?;
		ensure!(!extents.is_empty(), "descriptor has no extent lines");
		Ok(Self { cid, parent_cid, create_type, parent_hint, extents })
	}

	pub fn has_parent(&self) -> bool {
		self.parent_cid != NO_PARENT
	}

	pub fn capacity_sectors(&self) -> u64 {
		self.extents.iter().map(|e| e.sectors).sum()
	}
}

fn set_once<T>(slot: &mut Option<T>, value: T, key: &str) -> Result<()> {
	ensure!(slot.is_none(), "duplicate key {key}");
	*slot = Some(value);
	Ok(())
}

fn unquote(v: &str) -> &str {
	if v.len() >= 2 && v.starts_with('"') && v.ends_with('"') {
		&v[1..v.len() - 1]
	} else {
		v
	}
}

fn parse_cid(v: &str) -> Result<u32> {
	ensure!(!v.is_empty() && v.len() <= 8 && v.bytes().all(|b| b.is_ascii_hexdigit()), "invalid CID {v:?}");
	Ok(u32::from_str_radix(v, 16)?)
}

fn split_token(s: &str) -> (&str, &str) {
	let s = s.trim_start();
	match s.find(char::is_whitespace) {
		Some(i) => (&s[..i], &s[i..]),
		None => (s, ""),
	}
}

/// Returns `Ok(None)` if the line is not an extent line at all.
fn parse_extent_line(line: &str) -> Result<Option<ExtentLine>> {
	let (access, rest) = split_token(line);
	if !matches!(access, "RW" | "RDONLY" | "NOACCESS") || rest.trim_start().starts_with('=') {
		return Ok(None);
	}
	let (sectors, rest) = split_token(rest);
	let sectors: u64 = sectors.parse().with_context(|| format!("invalid extent size {sectors:?}"))?;
	let (kind, rest) = split_token(rest);
	ensure!(!kind.is_empty(), "extent line has no type");
	let rest = rest.trim();
	let (file, rest) = match rest.strip_prefix('"') {
		Some(r) => {
			let end = r.find('"').context("unterminated extent file name")?;
			(Some(r[..end].to_string()), r[end + 1..].trim())
		}
		None => (None, rest),
	};
	let offset = if rest.is_empty() { None } else { Some(rest.parse::<u64>().with_context(|| format!("invalid extent offset {rest:?}"))?) };
	Ok(Some(ExtentLine { access: access.to_string(), sectors, kind: kind.to_string(), file, offset }))
}

#[cfg(test)]
mod tests {
	use super::*;

	const DELTA: &str = concat!(
		"# Disk DescriptorFile\r\n",
		"version=1\r\n",
		"encoding=\"UTF-8\"\r\n",
		"CID=9353dbae\r\n",
		"parentCID=4368549c\r\n",
		"createType=\"twoGbMaxExtentSparse\"\r\n",
		"parentFileNameHint=\"athenaxp-000024.vmdk\"\r\n",
		"# Extent description\r\n",
		"RW 8323072 SPARSE \"athenaxp-000025-s001.vmdk\"\r\n",
		"RW 655360 SPARSE \"athenaxp 000025-s011.vmdk\"\r\n",
		"\r\n",
		"# The Disk Data Base \r\n",
		"#DDB\r\n",
		"\r\n",
		"ddb.longContentID = \"a007dbd81e839a9eabb1c4319353dbae\"\r\n",
	);

	#[test]
	fn parses_delta_descriptor() {
		let d = Descriptor::parse(DELTA).unwrap();
		assert_eq!(d.cid, 0x9353dbae);
		assert_eq!(d.parent_cid, 0x4368549c);
		assert!(d.has_parent());
		assert_eq!(d.create_type, "twoGbMaxExtentSparse");
		assert_eq!(d.parent_hint.as_deref(), Some("athenaxp-000024.vmdk"));
		assert_eq!(d.extents.len(), 2);
		assert_eq!(
			d.extents[0],
			ExtentLine { access: "RW".into(), sectors: 8323072, kind: "SPARSE".into(), file: Some("athenaxp-000025-s001.vmdk".into()), offset: None }
		);
		assert_eq!(d.extents[1].file.as_deref(), Some("athenaxp 000025-s011.vmdk"));
		assert_eq!(d.capacity_sectors(), 8323072 + 655360);
	}

	#[test]
	fn parses_base_descriptor_and_flat_offset() {
		let d = Descriptor::parse("CID=0a01aadb\nparentCID=ffffffff\ncreateType=\"monolithicFlat\"\nRW 2048 FLAT \"x-flat.vmdk\" 0\nRDONLY 64 ZERO\n").unwrap();
		assert_eq!(d.cid, 0x0a01aadb);
		assert!(!d.has_parent());
		assert_eq!(d.parent_hint, None);
		assert_eq!(d.extents[0].offset, Some(0));
		assert_eq!(d.extents[1], ExtentLine { access: "RDONLY".into(), sectors: 64, kind: "ZERO".into(), file: None, offset: None });
	}

	#[test]
	fn rejects_bad_descriptors() {
		assert!(Descriptor::parse("parentCID=ffffffff\ncreateType=\"x\"\nRW 1 SPARSE \"a\"\n").is_err(), "missing CID");
		assert!(Descriptor::parse("CID=1\nCID=2\nparentCID=ffffffff\ncreateType=\"x\"\nRW 1 SPARSE \"a\"\n").is_err(), "duplicate CID");
		assert!(Descriptor::parse("CID=xyz\nparentCID=ffffffff\ncreateType=\"x\"\nRW 1 SPARSE \"a\"\n").is_err(), "bad CID");
		assert!(Descriptor::parse("CID=1\nparentCID=ffffffff\ncreateType=\"x\"\n").is_err(), "no extents");
		assert!(Descriptor::parse("CID=1\nparentCID=ffffffff\ncreateType=\"x\"\nRW 1 SPARSE \"a\nfoo\n").is_err(), "garbage");
	}
}
