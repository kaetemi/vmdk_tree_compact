//! NTFS: boot sector, MFT records (update sequence fixups, attributes, run lists), the `$Bitmap`
//! free-cluster map, volume state (`$Volume` dirty flag, `$LogFile` restart area), and the
//! per-node free-grain map derived from them.

use crate::analysis::Bitset;
use crate::io::{le16, le32, le64};
use crate::partition::{self, Partition, PartitionTable};
use crate::view::Disk;
use anyhow::{bail, ensure, Context, Result};

pub const OEM_NTFS: &[u8; 8] = b"NTFS    ";
/// Update sequence fixups protect every 512 bytes regardless of the volume's sector size.
pub const FIXUP_STRIDE: usize = 512;

pub const ATTR_ATTRIBUTE_LIST: u32 = 0x20;
pub const ATTR_FILE_NAME: u32 = 0x30;
pub const ATTR_VOLUME_INFORMATION: u32 = 0x70;
pub const ATTR_DATA: u32 = 0x80;
const ATTR_END: u32 = 0xffff_ffff;
const ATTR_FLAG_COMPRESSED: u16 = 0x0001;
const ATTR_FLAG_ENCRYPTED: u16 = 0x4000;
const ATTR_FLAG_SPARSE: u16 = 0x8000;
const MFT_RECORD_IN_USE: u16 = 0x0001;
const VOLUME_IS_DIRTY: u16 = 0x0001;
const RESTART_VOLUME_IS_CLEAN: u16 = 0x0002;
const LOGFILE_NO_CLIENT: u16 = 0xffff;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BootSector {
	pub bytes_per_sector: u64,
	pub sectors_per_cluster: u64,
	pub total_sectors: u64,
	pub mft_lcn: u64,
	pub mftmirr_lcn: u64,
	pub record_size: u64,
	pub serial: u64,
}

impl BootSector {
	pub fn is_ntfs(b: &[u8]) -> bool {
		b.len() >= 11 && &b[3..11] == OEM_NTFS
	}

	pub fn parse(b: &[u8]) -> Result<Self> {
		ensure!(b.len() >= 512, "boot sector needs 512 bytes");
		ensure!(Self::is_ntfs(b), "OEM id is not \"NTFS    \"");
		ensure!(b[510] == 0x55 && b[511] == 0xaa, "boot sector has no 55aa signature");
		let bytes_per_sector = le16(b, 0x0b) as u64;
		ensure!(bytes_per_sector.is_power_of_two() && (256..=4096).contains(&bytes_per_sector), "bytes per sector {bytes_per_sector} is invalid");
		let raw = b[0x0d];
		let sectors_per_cluster = if raw <= 0x80 {
			raw as u64
		} else {
			let shift = 256 - raw as u32;
			ensure!(shift <= 16, "sectors per cluster byte {raw:#04x} is invalid");
			1u64 << shift
		};
		ensure!(sectors_per_cluster.is_power_of_two(), "sectors per cluster {sectors_per_cluster} is invalid");
		let cluster = bytes_per_sector * sectors_per_cluster;
		ensure!(cluster <= 2 << 20, "cluster size {cluster} is invalid");
		let total_sectors = le64(b, 0x28);
		ensure!(total_sectors >= sectors_per_cluster * 16, "total sectors {total_sectors} is implausibly small");
		let cpr = b[0x40] as i8;
		let record_size = if cpr > 0 {
			cpr as u64 * cluster
		} else {
			let shift = -(cpr as i32);
			ensure!((8..=16).contains(&shift), "clusters per MFT record byte {:#04x} is invalid", b[0x40]);
			1u64 << shift
		};
		ensure!(record_size.is_power_of_two() && (512..=65536).contains(&record_size), "MFT record size {record_size} is invalid");
		Ok(Self {
			bytes_per_sector,
			sectors_per_cluster,
			total_sectors,
			mft_lcn: le64(b, 0x30),
			mftmirr_lcn: le64(b, 0x38),
			record_size,
			serial: le64(b, 0x48),
		})
	}

	pub fn cluster_bytes(&self) -> u64 {
		self.bytes_per_sector * self.sectors_per_cluster
	}

	/// Clusters in the volume: whole clusters within `total_sectors`.
	pub fn clusters(&self) -> u64 {
		self.total_sectors / self.sectors_per_cluster
	}
}

/// Verifies and removes the update sequence protection of a multi-sector record in place.
pub fn apply_fixups(rec: &mut [u8], magic: &[u8; 4]) -> Result<()> {
	ensure!(rec.len() >= FIXUP_STRIDE && rec.len() % FIXUP_STRIDE == 0, "record size {} is not a multiple of {FIXUP_STRIDE}", rec.len());
	ensure!(&rec[0..4] == magic, "record magic is {:?}, expected {:?}", String::from_utf8_lossy(&rec[0..4]), String::from_utf8_lossy(magic));
	let usa_off = le16(rec, 4) as usize;
	let usa_count = le16(rec, 6) as usize;
	let sectors = rec.len() / FIXUP_STRIDE;
	ensure!(usa_count == sectors + 1, "update sequence array has {usa_count} entries, expected {}", sectors + 1);
	ensure!(usa_off % 2 == 0 && usa_off >= 8 && usa_off + usa_count * 2 <= FIXUP_STRIDE - 2, "update sequence array offset {usa_off} is invalid");
	let usn = [rec[usa_off], rec[usa_off + 1]];
	for i in 0..sectors {
		let end = (i + 1) * FIXUP_STRIDE - 2;
		ensure!(rec[end..end + 2] == usn, "sector {i} of the record fails the update sequence check (torn or misread record)");
		let src = usa_off + 2 + 2 * i;
		let (a, b) = (rec[src], rec[src + 1]);
		rec[end] = a;
		rec[end + 1] = b;
	}
	Ok(())
}

/// One run of a non-resident attribute: `len` clusters starting at `vcn`, at `lcn` (None = sparse).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Run {
	pub vcn: u64,
	pub len: u64,
	pub lcn: Option<u64>,
}

/// Decodes an NTFS mapping-pairs array. Each run: header byte (low nibble = length field size,
/// high nibble = offset field size), unsigned length, signed LCN delta from the previous run's LCN;
/// an offset size of zero denotes a sparse run.
pub fn decode_runs(data: &[u8], start_vcn: u64) -> Result<Vec<Run>> {
	let mut runs = Vec::new();
	let mut pos = 0usize;
	let mut vcn = start_vcn;
	let mut lcn: i64 = 0;
	loop {
		ensure!(pos < data.len(), "run list is not terminated");
		let h = data[pos];
		if h == 0 {
			return Ok(runs);
		}
		let (ls, os) = ((h & 0x0f) as usize, (h >> 4) as usize);
		ensure!((1..=8).contains(&ls) && os <= 8, "run header {h:#04x} at byte {pos} is invalid");
		ensure!(pos + 1 + ls + os <= data.len(), "run at byte {pos} extends past the attribute");
		let mut len = 0u64;
		for k in 0..ls {
			len |= (data[pos + 1 + k] as u64) << (8 * k);
		}
		ensure!(len > 0, "run at byte {pos} has zero length");
		let run_lcn = if os == 0 {
			None
		} else {
			let mut delta = 0u64;
			for k in 0..os {
				delta |= (data[pos + 1 + ls + k] as u64) << (8 * k);
			}
			// Sign-extend from os bytes.
			let shift = 64 - 8 * os as u32;
			let delta = ((delta << shift) as i64) >> shift;
			lcn = lcn.checked_add(delta).context("LCN overflow in run list")?;
			ensure!(lcn >= 0, "run at byte {pos} has negative LCN {lcn}");
			Some(lcn as u64)
		};
		runs.push(Run { vcn, len, lcn: run_lcn });
		vcn = vcn.checked_add(len).context("VCN overflow in run list")?;
		pos += 1 + ls + os;
	}
}

#[derive(Debug, Clone)]
pub enum AttrBody {
	Resident(Vec<u8>),
	NonResident { lowest_vcn: u64, highest_vcn: u64, data_size: u64, initialized_size: u64, runs: Vec<Run> },
}

#[derive(Debug, Clone)]
pub struct Attribute {
	pub type_code: u32,
	pub name: String,
	pub flags: u16,
	pub body: AttrBody,
}

#[derive(Debug, Clone)]
pub struct MftRecord {
	pub flags: u16,
	pub base_ref: u64,
	pub attrs: Vec<Attribute>,
}

fn utf16(b: &[u8]) -> String {
	let units: Vec<u16> = b.chunks_exact(2).map(|c| u16::from_le_bytes([c[0], c[1]])).collect();
	String::from_utf16_lossy(&units)
}

fn parse_attribute(a: &[u8]) -> Result<Attribute> {
	let type_code = le32(a, 0);
	let non_resident = a[8];
	let name_len = a[9] as usize;
	let name_off = le16(a, 0x0a) as usize;
	let flags = le16(a, 0x0c);
	let name = if name_len > 0 {
		ensure!(name_off + 2 * name_len <= a.len(), "attribute {type_code:#x} name lies outside the attribute");
		utf16(&a[name_off..name_off + 2 * name_len])
	} else {
		String::new()
	};
	let body = match non_resident {
		0 => {
			ensure!(a.len() >= 0x18, "resident attribute {type_code:#x} is too short");
			let vlen = le32(a, 0x10) as usize;
			let voff = le16(a, 0x14) as usize;
			ensure!(voff + vlen <= a.len(), "resident attribute {type_code:#x} value lies outside the attribute");
			AttrBody::Resident(a[voff..voff + vlen].to_vec())
		}
		1 => {
			ensure!(a.len() >= 0x40, "non-resident attribute {type_code:#x} is too short");
			let lowest_vcn = le64(a, 0x10);
			let highest_vcn = le64(a, 0x18);
			let mp_off = le16(a, 0x20) as usize;
			ensure!(mp_off >= 0x40 && mp_off < a.len(), "attribute {type_code:#x} mapping pairs offset {mp_off} is invalid");
			let runs = decode_runs(&a[mp_off..], lowest_vcn).with_context(|| format!("run list of attribute {type_code:#x}"))?;
			let end_vcn = runs.last().map(|r| r.vcn + r.len).unwrap_or(lowest_vcn);
			ensure!(
				end_vcn == highest_vcn.wrapping_add(1),
				"attribute {type_code:#x}: run list ends at VCN {end_vcn} but the header says highest VCN {highest_vcn}"
			);
			AttrBody::NonResident { lowest_vcn, highest_vcn, data_size: le64(a, 0x30), initialized_size: le64(a, 0x38), runs }
		}
		x => bail!("attribute {type_code:#x} has invalid non-resident flag {x}"),
	};
	Ok(Attribute { type_code, name, flags, body })
}

/// Parses a FILE record whose fixups have already been applied.
pub fn parse_record(rec: &[u8]) -> Result<MftRecord> {
	let attrs_off = le16(rec, 0x14) as usize;
	let flags = le16(rec, 0x16);
	let used = le32(rec, 0x18) as usize;
	let allocated = le32(rec, 0x1c) as usize;
	ensure!(allocated == rec.len(), "record says it is {allocated} bytes, expected {}", rec.len());
	ensure!(used <= rec.len() && attrs_off >= 0x18 && attrs_off < used, "record header is inconsistent (attributes at {attrs_off}, {used} bytes used)");
	let base_ref = le64(rec, 0x20);
	let mut attrs = Vec::new();
	let mut pos = attrs_off;
	loop {
		ensure!(pos + 4 <= used, "attribute list runs past the used part of the record");
		let t = le32(rec, pos);
		if t == ATTR_END {
			break;
		}
		ensure!(pos + 16 <= used, "attribute header at {pos} runs past the record");
		let len = le32(rec, pos + 4) as usize;
		ensure!(len >= 16 && len % 8 == 0 && pos + len <= used, "attribute at {pos} has invalid length {len}");
		attrs.push(parse_attribute(&rec[pos..pos + len]).with_context(|| format!("attribute at offset {pos}"))?);
		pos += len;
	}
	Ok(MftRecord { flags, base_ref, attrs })
}

impl MftRecord {
	pub fn has(&self, type_code: u32) -> bool {
		self.attrs.iter().any(|a| a.type_code == type_code)
	}

	pub fn file_names(&self) -> Vec<String> {
		self.attrs
			.iter()
			.filter(|a| a.type_code == ATTR_FILE_NAME)
			.filter_map(|a| match &a.body {
				AttrBody::Resident(v) if v.len() >= 0x42 => {
					let n = v[0x40] as usize;
					(0x42 + 2 * n <= v.len()).then(|| utf16(&v[0x42..0x42 + 2 * n]))
				}
				_ => None,
			})
			.collect()
	}

	pub fn unnamed(&self, type_code: u32) -> Option<&Attribute> {
		self.attrs.iter().find(|a| a.type_code == type_code && a.name.is_empty())
	}
}

/// The unnamed, non-resident, uncompressed `$DATA` of a system file, starting at VCN 0.
struct DataStream {
	data_size: u64,
	initialized_size: u64,
	runs: Vec<Run>,
	/// Bytes covered by the runs present in this record.
	mapped_bytes: u64,
}

fn system_data(rec: &MftRecord, what: &str, cluster_bytes: u64, clusters: u64) -> Result<DataStream> {
	let a = rec.unnamed(ATTR_DATA).with_context(|| format!("{what} has no unnamed $DATA attribute in its base record"))?;
	ensure!(
		a.flags & (ATTR_FLAG_COMPRESSED | ATTR_FLAG_ENCRYPTED | ATTR_FLAG_SPARSE) == 0,
		"{what} $DATA is compressed, encrypted or sparse (flags {:#06x})",
		a.flags
	);
	let AttrBody::NonResident { lowest_vcn, highest_vcn, data_size, initialized_size, runs } = &a.body else {
		bail!("{what} $DATA is resident");
	};
	ensure!(*lowest_vcn == 0, "{what} $DATA in the base record starts at VCN {lowest_vcn}");
	for r in runs {
		if let Some(l) = r.lcn {
			ensure!(l.checked_add(r.len).is_some_and(|e| e <= clusters), "{what} run at LCN {l} (+{}) lies outside the {clusters}-cluster volume", r.len);
		}
	}
	Ok(DataStream {
		data_size: *data_size,
		initialized_size: *initialized_size,
		runs: runs.clone(),
		mapped_bytes: highest_vcn.wrapping_add(1).saturating_mul(cluster_bytes),
	})
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LogState {
	/// Restart area says the volume was cleanly unmounted.
	Clean,
	/// Log has active clients and no clean flag: the state on disk may need log replay.
	Unclean,
	/// $LogFile reset to 0xff (e.g. by chkdsk or ntfs-3g): nothing to replay.
	Empty,
}

pub struct Volume {
	/// Byte offset of the volume on the virtual disk.
	pub offset: u64,
	pub boot: BootSector,
	pub ntfs_version: (u8, u8),
	pub volume_flags: u16,
	pub log: LogState,
	/// MFT record 0 carries an $ATTRIBUTE_LIST (fragmented MFT); only its base-record runs were used.
	pub mft_has_attribute_list: bool,
	pub bitmap: Vec<u8>,
	pub bitmap_data_size: u64,
	pub used_clusters: u64,
}

struct VolCtx<'a> {
	disk: &'a dyn Disk,
	offset: u64,
	cluster_bytes: u64,
	clusters: u64,
}

impl VolCtx<'_> {
	/// Reads `buf.len()` bytes at byte `pos` of a non-resident stream.
	fn read_stream(&self, runs: &[Run], pos: u64, buf: &mut [u8]) -> Result<()> {
		let cb = self.cluster_bytes;
		let mut done = 0usize;
		while done < buf.len() {
			let at = pos + done as u64;
			let vcn = at / cb;
			let run = runs.iter().find(|r| r.vcn <= vcn && vcn < r.vcn + r.len).with_context(|| format!("VCN {vcn} is not mapped by the run list"))?;
			let lcn = run.lcn.with_context(|| format!("VCN {vcn} lies in a sparse run"))? + (vcn - run.vcn);
			ensure!(lcn < self.clusters, "LCN {lcn} lies outside the volume");
			let within = at % cb;
			let n = ((run.vcn + run.len - vcn) * cb - within).min((buf.len() - done) as u64) as usize;
			self.disk.read_at(self.offset + lcn * cb + within, &mut buf[done..done + n])?;
			done += n;
		}
		Ok(())
	}
}

impl Volume {
	/// Opens the NTFS volume whose boot sector is at byte `offset`; `max_bytes` is the partition size.
	pub fn open(disk: &dyn Disk, offset: u64, max_bytes: u64) -> Result<Self> {
		let mut bs = [0u8; 512];
		disk.read_at(offset, &mut bs)?;
		let boot = BootSector::parse(&bs).context("boot sector")?;
		let cb = boot.cluster_bytes();
		let clusters = boot.clusters();
		let vol_bytes = boot.total_sectors * boot.bytes_per_sector;
		ensure!(vol_bytes <= max_bytes, "volume ({vol_bytes} bytes) is larger than its partition ({max_bytes} bytes)");
		ensure!(boot.mft_lcn < clusters && boot.mftmirr_lcn < clusters, "MFT LCN {} / MFTMirr LCN {} lie outside the volume", boot.mft_lcn, boot.mftmirr_lcn);
		let ctx = VolCtx { disk, offset, cluster_bytes: cb, clusters };
		let rs = boot.record_size as usize;

		// $MFT record 0, located through the boot sector.
		let mut rec0 = vec![0u8; rs];
		disk.read_at(offset + boot.mft_lcn * cb, &mut rec0)?;
		apply_fixups(&mut rec0, b"FILE").context("$MFT record 0")?;
		let r0 = parse_record(&rec0).context("$MFT record 0")?;
		check_system_record(&r0, "$MFT")?;
		let mft = system_data(&r0, "$MFT", cb, clusters)?;
		ensure!(mft.runs.first().and_then(|r| r.lcn) == Some(boot.mft_lcn), "$MFT run list does not start at the boot sector's MFT LCN {}", boot.mft_lcn);
		let mft_has_attribute_list = r0.has(ATTR_ATTRIBUTE_LIST);
		let mft_readable = mft.mapped_bytes.min(mft.data_size).min(mft.initialized_size);
		let read_record = |n: u64, name: &str| -> Result<MftRecord> {
			let end = (n + 1) * boot.record_size;
			ensure!(
				end <= mft_readable,
				"MFT record {n} ({name}) lies beyond the {mft_readable} bytes of $MFT mapped by the base record{}",
				if mft_has_attribute_list { " (the rest is behind an $ATTRIBUTE_LIST, which is not supported)" } else { "" }
			);
			let mut rec = vec![0u8; rs];
			ctx.read_stream(&mft.runs, n * boot.record_size, &mut rec)?;
			apply_fixups(&mut rec, b"FILE").with_context(|| format!("MFT record {n} ({name})"))?;
			let r = parse_record(&rec).with_context(|| format!("MFT record {n} ({name})"))?;
			check_system_record(&r, name)?;
			Ok(r)
		};

		// $Bitmap (record 6).
		let r6 = read_record(6, "$Bitmap")?;
		let bm = system_data(&r6, "$Bitmap", cb, clusters)?;
		let need = clusters.div_ceil(8);
		ensure!(bm.data_size >= need, "$Bitmap holds {} bytes but {clusters} clusters need {need}", bm.data_size);
		ensure!(bm.initialized_size >= need, "$Bitmap initialized size {} is below the {need} bytes needed", bm.initialized_size);
		ensure!(
			bm.mapped_bytes >= need,
			"$Bitmap base record maps only {} bytes of {need}{}",
			bm.mapped_bytes,
			if r6.has(ATTR_ATTRIBUTE_LIST) { " (the rest is behind an $ATTRIBUTE_LIST, which is not supported)" } else { "" }
		);
		let mut bitmap = vec![0u8; need as usize];
		ctx.read_stream(&bm.runs, 0, &mut bitmap).context("reading $Bitmap")?;
		let used_clusters = (0..clusters).filter(|&c| bit(&bitmap, c)).count() as u64;

		// The bitmap must mark the boot sector and the metadata we just walked through as in use.
		ensure!(bit(&bitmap, 0), "$Bitmap marks cluster 0 (boot sector) as free");
		ensure!(bit(&bitmap, boot.mftmirr_lcn), "$Bitmap marks the $MFTMirr cluster as free");
		for (what, runs, bytes) in [("$MFT", &mft.runs, mft.mapped_bytes.min(mft.data_size)), ("$Bitmap", &bm.runs, need)] {
			let last_vcn = bytes.div_ceil(cb);
			for r in runs.iter().filter(|r| r.vcn < last_vcn) {
				let lcn = r.lcn.with_context(|| format!("{what} has a sparse run"))?;
				let n = r.len.min(last_vcn - r.vcn);
				if let Some(c) = (lcn..lcn + n).find(|&c| !bit(&bitmap, c)) {
					bail!("$Bitmap marks cluster {c} of {what} as free: the bitmap is not being read correctly");
				}
			}
		}

		// $Volume (record 3): version and dirty flag.
		let r3 = read_record(3, "$Volume")?;
		let vi = r3.unnamed(ATTR_VOLUME_INFORMATION).context("$Volume has no $VOLUME_INFORMATION")?;
		let AttrBody::Resident(vi) = &vi.body else { bail!("$VOLUME_INFORMATION is non-resident") };
		ensure!(vi.len() >= 12, "$VOLUME_INFORMATION is only {} bytes", vi.len());
		let ntfs_version = (vi[8], vi[9]);
		let volume_flags = le16(vi, 10);

		// $LogFile (record 2): restart area clean flag.
		let r2 = read_record(2, "$LogFile")?;
		let lf = system_data(&r2, "$LogFile", cb, clusters)?;
		let log = log_state(&ctx, &lf).context("$LogFile restart area")?;

		Ok(Self { offset, boot, ntfs_version, volume_flags, log, mft_has_attribute_list, bitmap, bitmap_data_size: bm.data_size, used_clusters })
	}

	pub fn cluster_bytes(&self) -> u64 {
		self.boot.cluster_bytes()
	}

	pub fn clusters(&self) -> u64 {
		self.boot.clusters()
	}

	pub fn total_bytes(&self) -> u64 {
		self.clusters() * self.cluster_bytes()
	}

	pub fn free_clusters(&self) -> u64 {
		self.clusters() - self.used_clusters
	}

	pub fn free_bytes(&self) -> u64 {
		self.free_clusters() * self.cluster_bytes()
	}

	pub fn is_dirty(&self) -> bool {
		self.volume_flags & VOLUME_IS_DIRTY != 0
	}

	/// The on-disk `$Bitmap` can be trusted only if the volume was cleanly unmounted.
	pub fn is_consistent(&self) -> bool {
		!self.is_dirty() && self.log != LogState::Unclean
	}

	pub fn state(&self) -> String {
		let log = match self.log {
			LogState::Clean => "log clean",
			LogState::Unclean => "LOG UNCLEAN",
			LogState::Empty => "log empty",
		};
		if self.is_dirty() {
			format!("DIRTY, {log}")
		} else {
			log.to_string()
		}
	}

	/// Marks every grain that lies entirely inside free clusters of this volume.
	pub fn mark_free_grains(&self, grain_bytes: u64, out: &mut Bitset) {
		free_grains_from_bitmap(&self.bitmap, self.clusters(), self.cluster_bytes(), self.offset, grain_bytes, out);
	}
}

fn check_system_record(r: &MftRecord, name: &str) -> Result<()> {
	ensure!(r.flags & MFT_RECORD_IN_USE != 0, "{name} record is not in use");
	ensure!(r.base_ref == 0, "{name} record is an extension record");
	let names = r.file_names();
	ensure!(names.iter().any(|n| n == name), "record is not {name} (file names {names:?})");
	Ok(())
}

/// Bit set = cluster in use; LSB first.
fn bit(bitmap: &[u8], c: u64) -> bool {
	(bitmap[(c / 8) as usize] >> (c % 8)) & 1 != 0
}

/// Grain `g` is free iff every byte of `[g*gb, (g+1)*gb)` lies in a cluster `< clusters` whose bit is clear.
/// Anything outside the cluster area of the volume counts as in use.
pub fn free_grains_from_bitmap(bitmap: &[u8], clusters: u64, cluster_bytes: u64, vol_offset: u64, grain_bytes: u64, out: &mut Bitset) {
	let vol_end = vol_offset + clusters * cluster_bytes;
	let first = vol_offset.div_ceil(grain_bytes);
	let last = (vol_end / grain_bytes).min(out.len() as u64);
	for g in first..last {
		let a = g * grain_bytes - vol_offset;
		let (c0, c1) = (a / cluster_bytes, (a + grain_bytes - 1) / cluster_bytes);
		if (c0..=c1).all(|c| !bit(bitmap, c)) {
			out.set(g as usize);
		}
	}
}

struct Restart {
	current_lsn: u64,
	client_in_use_list: u16,
	flags: u16,
}

fn parse_restart(p: &mut [u8]) -> Result<Restart> {
	let magic: [u8; 4] = p[0..4].try_into().unwrap();
	ensure!(&magic == b"RSTR" || &magic == b"CHKD", "restart page magic is {:?}", String::from_utf8_lossy(&magic));
	// A page rewritten by chkdsk may carry no update sequence array.
	if !(&magic == b"CHKD" && le16(p, 6) == 0) {
		apply_fixups(p, &magic)?;
	}
	let ra = le16(p, 0x18) as usize;
	ensure!(ra % 8 == 0 && ra + 0x30 <= p.len(), "restart area offset {ra} is invalid");
	Ok(Restart { current_lsn: le64(p, ra), client_in_use_list: le16(p, ra + 0x0c), flags: le16(p, ra + 0x0e) })
}

fn log_state(ctx: &VolCtx, lf: &DataStream) -> Result<LogState> {
	ensure!(lf.data_size >= 8192 && lf.initialized_size >= 8192 && lf.mapped_bytes >= 8192, "$LogFile is too small ({} bytes)", lf.data_size);
	let mut first = vec![0u8; 4096];
	ctx.read_stream(&lf.runs, 0, &mut first)?;
	if first.iter().all(|&b| b == 0xff) {
		return Ok(LogState::Empty);
	}
	let page = le32(&first, 0x10) as u64;
	ensure!(page.is_power_of_two() && (512..=65536).contains(&page) && 2 * page <= lf.data_size.min(lf.mapped_bytes), "restart page size {page} is invalid");
	let mut pages = Vec::new();
	let mut errors = Vec::new();
	for k in 0..2u64 {
		let mut p = vec![0u8; page as usize];
		ctx.read_stream(&lf.runs, k * page, &mut p)?;
		match parse_restart(&mut p) {
			Ok(r) => pages.push(r),
			Err(e) => errors.push(format!("page {k}: {e:#}")),
		}
	}
	let best = pages.iter().max_by_key(|r| r.current_lsn).with_context(|| format!("no valid restart page ({})", errors.join("; ")))?;
	Ok(if best.client_in_use_list == LOGFILE_NO_CLIENT || best.flags & RESTART_VOLUME_IS_CLEAN != 0 { LogState::Clean } else { LogState::Unclean })
}

/// What one partition turned out to be.
pub struct PartitionInfo {
	pub partition: Partition,
	/// Some if the partition holds an NTFS volume.
	pub volume: Option<Volume>,
}

/// File system view of one node: partitions, NTFS volumes and the grains free at this node.
pub struct NodeFs {
	pub table: PartitionTable,
	pub partitions: Vec<PartitionInfo>,
	pub free: Bitset,
	pub warnings: Vec<String>,
}

impl NodeFs {
	pub fn volumes(&self) -> impl Iterator<Item = (&Partition, &Volume)> {
		self.partitions.iter().filter_map(|p| p.volume.as_ref().map(|v| (&p.partition, v)))
	}
}

pub fn scan_node(disk: &dyn Disk, total_grains: u64, grain_bytes: u64) -> Result<NodeFs> {
	let table = partition::scan(disk).context("partition table")?;
	let mut free = Bitset::new(total_grains as usize);
	let mut partitions = Vec::new();
	let mut warnings = Vec::new();
	for p in &table.partitions {
		ensure!(p.offset() + p.size() <= disk.size(), "partition {} extends past the end of the disk", p.number);
		let mut bs = [0u8; 512];
		disk.read_at(p.offset(), &mut bs)?;
		let volume = if BootSector::is_ntfs(&bs) {
			let v = Volume::open(disk, p.offset(), p.size()).with_context(|| format!("NTFS volume in partition {} at LBA {}", p.number, p.start_lba))?;
			if v.is_consistent() {
				v.mark_free_grains(grain_bytes, &mut free);
			} else {
				warnings.push(format!(
					"NTFS volume in partition {} is not cleanly unmounted ({}); its free clusters are treated as in use",
					p.number,
					v.state()
				));
			}
			Some(v)
		} else {
			None
		};
		partitions.push(PartitionInfo { partition: p.clone(), volume });
	}
	let free_cluster_bytes: u64 = partitions.iter().filter_map(|p| p.volume.as_ref()).filter(|v| v.is_consistent()).map(|v| v.free_bytes()).sum();
	let free_grain_bytes = free.count() * grain_bytes;
	ensure!(
		free_grain_bytes <= free_cluster_bytes,
		"free grains ({free_grain_bytes} bytes) exceed the free clusters ({free_cluster_bytes} bytes): free map computation is wrong"
	);
	for (_, v) in partitions.iter().filter_map(|p| p.volume.as_ref().map(|v| (p, v))) {
		ensure!(v.free_bytes() <= v.total_bytes(), "NTFS free space exceeds the volume size");
	}
	Ok(NodeFs { table, partitions, free, warnings })
}

/// Scans every node of the tree through its chain view. Indexed by node.
pub fn scan_tree(t: &crate::tree::Tree) -> Result<Vec<NodeFs>> {
	(0..t.len())
		.map(|n| {
			let view = crate::view::ChainView::new(t, n);
			scan_node(&view, t.total_grains, t.grain_bytes()).with_context(|| format!("file system at node {} ({})", t.nodes[n].layer.file_name, t.label(n)))
		})
		.collect()
}

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn decodes_run_lists() {
		// 0x21: len 1 byte, off 2 bytes. Run 1: 0x18 clusters at 0x5634; run 2 (0x31): 0x40 at +0x123456 (positive);
		// run 3 (0x11): 0x10 clusters at delta -0x10 (0xf0); run 4 (0x01): sparse 0x20 clusters; run 5: 0x21 len 8 at delta -0x100.
		let data = [
			0x21, 0x18, 0x34, 0x56, //
			0x31, 0x40, 0x56, 0x34, 0x12, //
			0x11, 0x10, 0xf0, //
			0x01, 0x20, //
			0x21, 0x08, 0x00, 0xff, //
			0x00, 0xaa, // terminator, then padding
		];
		let runs = decode_runs(&data, 0).unwrap();
		let a = 0x5634u64;
		let b = a + 0x123456;
		let c = b - 0x10;
		let d = c - 0x100;
		assert_eq!(
			runs,
			vec![
				Run { vcn: 0, len: 0x18, lcn: Some(a) },
				Run { vcn: 0x18, len: 0x40, lcn: Some(b) },
				Run { vcn: 0x58, len: 0x10, lcn: Some(c) },
				Run { vcn: 0x68, len: 0x20, lcn: None },
				Run { vcn: 0x88, len: 0x08, lcn: Some(d) },
			]
		);
	}

	#[test]
	fn rejects_bad_run_lists() {
		assert!(decode_runs(&[0x21, 0x18, 0x34], 0).is_err(), "truncated");
		assert!(decode_runs(&[0x11, 0x01, 0x05], 0).is_err(), "unterminated");
		assert!(decode_runs(&[0x11, 0x01, 0xff, 0x00], 0).is_err(), "negative LCN");
		assert!(decode_runs(&[0x10, 0x05, 0x00], 0).is_err(), "zero-size length field");
		assert!(decode_runs(&[0x11, 0x00, 0x05, 0x00], 0).is_err(), "zero length");
	}

	fn record_with_usa(size: usize, usn: u16, originals: &[[u8; 2]]) -> Vec<u8> {
		let mut r = vec![0u8; size];
		r[0..4].copy_from_slice(b"FILE");
		r[4..6].copy_from_slice(&0x30u16.to_le_bytes());
		r[6..8].copy_from_slice(&((size / 512 + 1) as u16).to_le_bytes());
		r[0x30..0x32].copy_from_slice(&usn.to_le_bytes());
		for (i, o) in originals.iter().enumerate() {
			r[0x32 + 2 * i..0x34 + 2 * i].copy_from_slice(o);
			let end = (i + 1) * 512 - 2;
			r[end..end + 2].copy_from_slice(&usn.to_le_bytes());
		}
		r
	}

	#[test]
	fn applies_fixups() {
		let mut r = record_with_usa(1024, 0x0007, &[[0xaa, 0xbb], [0xcc, 0xdd]]);
		apply_fixups(&mut r, b"FILE").unwrap();
		assert_eq!(&r[510..512], &[0xaa, 0xbb]);
		assert_eq!(&r[1022..1024], &[0xcc, 0xdd]);

		// Torn write: second sector's tail does not carry the update sequence number.
		let mut r = record_with_usa(1024, 0x0007, &[[0xaa, 0xbb], [0xcc, 0xdd]]);
		r[1022] = 0x08;
		assert!(apply_fixups(&mut r, b"FILE").is_err());

		// Wrong magic, wrong count.
		let mut r = record_with_usa(1024, 0x0007, &[[0, 0], [0, 0]]);
		assert!(apply_fixups(&mut r, b"INDX").is_err());
		let mut r = record_with_usa(1024, 0x0007, &[[0, 0], [0, 0]]);
		r[6] = 4;
		assert!(apply_fixups(&mut r, b"FILE").is_err());
	}

	#[test]
	fn parses_boot_sector_geometry() {
		let mut b = [0u8; 512];
		b[3..11].copy_from_slice(OEM_NTFS);
		b[0x0b..0x0d].copy_from_slice(&512u16.to_le_bytes());
		b[0x0d] = 8;
		b[0x28..0x30].copy_from_slice(&83875301u64.to_le_bytes());
		b[0x30..0x38].copy_from_slice(&786432u64.to_le_bytes());
		b[0x38..0x40].copy_from_slice(&2u64.to_le_bytes());
		b[0x40] = 0xf6; // -10: 1024-byte records
		b[510] = 0x55;
		b[511] = 0xaa;
		let bs = BootSector::parse(&b).unwrap();
		assert_eq!(bs.cluster_bytes(), 4096);
		assert_eq!(bs.record_size, 1024);
		assert_eq!(bs.clusters(), 83875301 / 8);
		b[0x0d] = 0xf4; // -12: 4096 sectors per cluster encoding used for large clusters
		assert_eq!(BootSector::parse(&b).unwrap().sectors_per_cluster, 4096);
	}

	#[test]
	fn maps_free_clusters_to_grains() {
		// Volume at sector 63 (offset 32256), 4 KiB clusters, 64 KiB grains, 64 clusters.
		let (cb, gb, off, clusters) = (4096u64, 65536u64, 63 * 512u64, 64u64);
		let mut bitmap = vec![0u8; 8];
		bitmap[0] = 0x01; // cluster 0 in use (boot)
		let mut out = Bitset::new(8);
		free_grains_from_bitmap(&bitmap, clusters, cb, off, gb, &mut out);
		// Grain 0 holds the MBR and the volume start; the volume ends at 32256 + 262144 = 294400,
		// so grain 4 ([262144, 327680)) is partly outside. Grains 1..=3 are free.
		assert_eq!(out.iter_ones().collect::<Vec<_>>(), vec![1, 2, 3]);

		// Grain 1 covers volume bytes [33280, 98816) = clusters 8..=24, grain 2 clusters 24..=40:
		// cluster 24 is shared by both, cluster 7 lies in grain 0 (not free anyway), 25 only in grain 2.
		for (used, expect) in [(24u64, vec![3]), (8, vec![2, 3]), (7, vec![1, 2, 3]), (25, vec![1, 3])] {
			let mut bm = bitmap.clone();
			bm[(used / 8) as usize] |= 1 << (used % 8);
			let mut out = Bitset::new(8);
			free_grains_from_bitmap(&bm, clusters, cb, off, gb, &mut out);
			assert_eq!(out.iter_ones().collect::<Vec<_>>(), expect, "cluster {used} in use");
		}
	}
}
