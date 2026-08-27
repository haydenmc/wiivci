//! Reading the source Wii disc image via the [`nod`] crate.
//!
//! `nod` transparently handles ISO / RVZ / WBFS / CISO / NKit / GCZ inputs and performs Wii
//! partition AES decryption internally. We open the disc in **decrypted mode**
//! (`rebuild_encryption: false`) so that reading the disc stream yields the logical disc
//! image with partition data already decrypted *and hash blocks intact* — precisely the
//! representation the Wii U VC NFS format stores.
//!
//! The Wii common key is read by `nod` from its own key store; callers must ensure it is
//! available (see [`crate::keys`]). We additionally extract the game partition's `ticket.bin`
//! and `tmd.bin`, which become `code/rvlt.tik` / `code/rvlt.tmd` in the output package.

use std::io::{Read, Seek, SeekFrom};
use std::path::{Path, PathBuf};

use nod::{Disc, OpenOptions, PartitionKind, SECTOR_SIZE};

use crate::error::{Error, Result};

/// Logical (hash-stripped) bytes per disc cluster (must match [`crate::consts::CLUSTER_DATA`]).
const LOG_CLUSTER: u64 = crate::consts::CLUSTER_DATA as u64;
/// Clusters per Wii hash group.
const GROUP_CLUSTERS: u64 = 64;
/// Logical bytes covered by one hash group.
const GROUP_BYTES: u64 = GROUP_CLUSTERS * LOG_CLUSTER;

/// Upper bound on the size of a `main.dol` we are willing to parse and buffer.
///
/// The DOL header is 18 attacker-controlled `(offset, size)` pairs whose maximum end determines the
/// allocation, so a corrupt header can otherwise ask for ~8 GiB before the read fails. A real DOL
/// must load into console RAM (MEM1 24 MiB + MEM2 64 MiB = 88 MiB), so 128 MiB is generous headroom
/// that no valid disc reaches.
const MAX_DOL_SIZE: u64 = 128 << 20;

/// Returns `true` iff the `len` logical bytes at `off` in `r` are all zero. Reads in chunks with an
/// early exit on the first non-zero byte, so non-zero regions cost almost nothing.
fn region_is_zero<R: Read + Seek + ?Sized>(r: &mut R, off: u64, len: u64) -> std::io::Result<bool> {
    r.seek(SeekFrom::Start(off))?;
    let mut remaining = len;
    let mut buf = vec![0u8; 1 << 20];
    while remaining > 0 {
        let n = remaining.min(buf.len() as u64) as usize;
        r.read_exact(&mut buf[..n])?;
        if buf[..n].iter().any(|&b| b != 0) {
            return Ok(false);
        }
        remaining -= n as u64;
    }
    Ok(true)
}

/// The hash groups fully contained in the logical byte range `[off, off+len)`, as a `first..end`
/// range of group indices (`group_bytes` = bytes per group). Empty (`end <= start`) when the range
/// spans no whole group — those boundary groups also cover neighbouring data and must be kept.
fn fully_contained_groups(off: u64, len: u64, group_bytes: u64) -> std::ops::Range<u64> {
    let start = off.div_ceil(group_bytes);
    let end = (off + len) / group_bytes;
    start..end
}

fn be32(b: &[u8]) -> u32 {
    u32::from_be_bytes([b[0], b[1], b[2], b[3]])
}

/// Total size of a DOL from its 0x100-byte header: 18 sections (7 text + 11 data), offsets at
/// `0x00..`, sizes at `0x90..`; the size is the largest section end, never below the header itself.
///
/// Every section is validated against `max` (see [`MAX_DOL_SIZE`]) so a corrupt header reports a
/// descriptive error instead of driving a huge allocation.
fn dol_size_from_header(header: &[u8; 0x100], max: u64) -> Result<u64> {
    let mut size = 0x100u64;
    for i in 0..18 {
        // Both fields are `u32`, so the sum cannot overflow `u64`.
        let off = be32(&header[i * 4..]) as u64;
        let sz = be32(&header[0x90 + i * 4..]) as u64;
        let end = off + sz;
        if end > max {
            return Err(Error::UnsupportedDisc(format!(
                "main.dol section {i} ends at {end} (offset {off} + size {sz}), past the \
                 {max}-byte limit"
            )));
        }
        size = size.max(end);
    }
    Ok(size)
}

/// The inclusive range of hash-group indices touched by the logical extent `[off, off+len)`, or
/// `None` when the extent is empty (a zero-length FST entry marks nothing, whatever its offset).
///
/// Errors when the extent reaches past `data_size`, the logical size of the partition's data
/// region. That bound is deliberately the *byte* end of the data region rather than the end of the
/// last (possibly partial) hash group: it is exactly the point past which the region cannot be
/// read, so the marking path and the zero-scan path reject the same corrupt entries. Previously the
/// marking path silently discarded such extents while the zero-scan path failed with a bare
/// `UnexpectedEof`.
fn extent_groups(
    off: u64,
    len: u64,
    data_size: u64,
) -> Result<Option<std::ops::RangeInclusive<u64>>> {
    if len == 0 {
        return Ok(None);
    }
    let Some(end) = off.checked_add(len).filter(|&end| end <= data_size) else {
        return Err(Error::UnsupportedDisc(format!(
            "disc extent at offset {off} spans {len} bytes, past the end of the {data_size}-byte \
             partition data region"
        )));
    };
    let first = off / LOG_CLUSTER / GROUP_CLUSTERS;
    let last = (end - 1) / LOG_CLUSTER / GROUP_CLUSTERS;
    Ok(Some(first..=last))
}

/// The whole hash groups zero-fill trimming would drop for a file at `[off, off+len)`, or `None`
/// when the file is too small to be worth scanning or covers no whole group.
///
/// Pure: says nothing about whether the file *is* zero — the caller scans it (see
/// [`region_is_zero`]) and only then applies the range.
fn zero_trim_groups(off: u64, len: u64) -> Option<std::ops::Range<u64>> {
    /// Files too small to contain whole groups are never candidates.
    const MIN_ZERO_FILE_GROUPS: u64 = 2;
    if len < MIN_ZERO_FILE_GROUPS * GROUP_BYTES {
        return None;
    }
    let groups = fully_contained_groups(off, len, GROUP_BYTES);
    (groups.end > groups.start).then_some(groups)
}

/// Decide which 64-cluster hash groups the NFS stores, as coalesced `(first_group, num_groups)`
/// runs. The pure core of [`SourceDisc::used_data_group_runs`]; all disc I/O happens in that
/// wrapper, which passes its results in.
///
/// * `extents` — every logical `(offset, length)` that must be stored: the boot structures followed
///   by every FST file entry, in disc order (the order errors are reported in).
/// * `clusters` — logical clusters in the partition's data region; fixes both the group count
///   (`ceil(clusters / 64)`, so the last group may be partial) and the in-bounds byte limit.
/// * `skip_gaps` — when `false`, every group is stored regardless of `extents`.
/// * `zero_extents` — the subset of `extents` confirmed to be entirely zero; the whole groups they
///   contain are dropped again. Empty unless `--trim-zeros`. Applied *after* the `skip_gaps` fill,
///   so trimming punches holes even when gap-skipping is off.
fn plan_group_runs(
    extents: &[(u64, u64)],
    clusters: u64,
    skip_gaps: bool,
    zero_extents: &[(u64, u64)],
) -> Result<Vec<(u32, u32)>> {
    let ngroups = clusters.div_ceil(GROUP_CLUSTERS) as usize;
    let data_size = clusters * LOG_CLUSTER;
    let mut used = vec![false; ngroups];

    for &(off, len) in extents {
        // In-bounds by construction: `extent_groups` rejects anything reaching past `data_size`.
        if let Some(groups) = extent_groups(off, len, data_size)? {
            for g in groups {
                used[g as usize] = true;
            }
        }
    }

    // Store every group when gap-skipping is disabled (the whole partition).
    if !skip_gaps {
        used.fill(true);
    }

    // Zero-fill trimming: drop the groups lying fully inside a wholly-zero file. Only whole groups
    // are cleared (never a boundary group), so every cleared group is genuinely all-zero and
    // reconstructs identically on read.
    for &(off, len) in zero_extents {
        if let Some(groups) = zero_trim_groups(off, len) {
            for g in groups {
                if (g as usize) < ngroups {
                    used[g as usize] = false;
                }
            }
        }
    }

    // Coalesce marked groups into runs.
    let mut runs = Vec::new();
    let mut open: Option<(u32, u32)> = None;
    for (g, &u) in used.iter().enumerate() {
        match (&mut open, u) {
            (Some((_, n)), true) => *n += 1,
            (Some(_), false) => runs.push(open.take().unwrap()),
            (None, true) => open = Some((g as u32, 1)),
            (None, false) => {}
        }
    }
    if let Some(r) = open {
        runs.push(r);
    }
    Ok(runs)
}

/// The data partition's `main.dol` and its offset within the decrypted partition data.
pub struct MainDol {
    /// Logical offset of `main.dol` within the decrypted data partition.
    pub offset: u64,
    /// The `main.dol` bytes.
    pub data: Vec<u8>,
}

/// Size of a Wii/GC disc sector: 0x8000 bytes. Re-exported from `nod` for convenience.
pub const DISC_SECTOR_SIZE: usize = SECTOR_SIZE;

/// A source Wii disc opened for reading in decrypted mode.
pub struct SourceDisc {
    disc: Disc,
    path: PathBuf,
    game_id: [u8; 6],
    disc_size: u64,
    /// The data partition's sector span (start of partition .. end of partition data).
    data_partition: PartitionSpan,
    /// Every partition's sector span, sorted ascending by start sector.
    partitions: Vec<PartitionSpan>,
    raw_ticket: Vec<u8>,
    raw_tmd: Vec<u8>,
}

/// A `Read + Seek` trait object alias so a decrypted disc stream can be passed dynamically.
///
/// `Seek` is not an auto-trait, so `dyn Read + Seek` is not expressible directly; this combined
/// supertrait (with a blanket impl) gives us an object-safe `dyn ReadSeek`.
pub trait ReadSeek: Read + Seek {}
impl<T: Read + Seek + ?Sized> ReadSeek for T {}

/// A source of a decrypted logical Wii disc for the NFS encoder ([`crate::nfs::build_nfs`]).
///
/// Provides the disc bytes (partition data decrypted, hash blocks present — the representation
/// the Wii U VC NFS format stores), the partition layout, and the total size. Implemented by
/// [`SourceDisc`] (a real Wii disc read via `nod`) and by the synthetic Wii disc authored for a
/// GameCube/Nintendont inject (see `crate::wii_author`).
pub trait DecryptedDisc {
    /// The logical disc size in bytes.
    fn disc_size(&self) -> u64;
    /// The decrypted disc byte stream (partition data decrypted, hash blocks intact).
    fn disc_stream(&mut self) -> &mut dyn ReadSeek;
}

/// The sector range occupied by a partition on the logical disc.
#[derive(Clone, Copy, Debug)]
pub struct PartitionSpan {
    /// `nod` partition index (for [`SourceDisc::partition_h3_table`]).
    pub index: usize,
    /// First sector of the partition (its header/ticket/tmd).
    pub start_sector: u32,
    /// First sector of the (now-decrypted) partition data.
    pub data_start_sector: u32,
    /// One past the last sector of the partition data.
    pub data_end_sector: u32,
}

impl SourceDisc {
    /// Open a Wii disc image in decrypted mode.
    pub fn open(path: impl AsRef<Path>) -> Result<Self> {
        let path = path.as_ref().to_path_buf();
        let options = OpenOptions {
            rebuild_encryption: false,
            ..Default::default()
        };
        let disc = Disc::new_with_options(&path, &options)?;

        let header = disc.header();
        if !header.is_wii() {
            return Err(Error::UnsupportedDisc(format!(
                "'{}' is not a Wii disc (GameCube images are injected via GcImage::open, not \
                 SourceDisc::open)",
                path.display()
            )));
        }
        let mut game_id = [0u8; 6];
        game_id.copy_from_slice(&header.game_id);
        let disc_size = disc.disc_size();

        // Collect every partition span; identify the data (game) partition.
        let span_of = |p: &nod::PartitionInfo| PartitionSpan {
            index: p.index,
            start_sector: p.start_sector,
            data_start_sector: p.data_start_sector,
            data_end_sector: p.data_end_sector,
        };
        let mut partitions: Vec<PartitionSpan> = disc.partitions().iter().map(span_of).collect();
        partitions.sort_by_key(|p| p.start_sector);
        let data_partition = disc
            .partitions()
            .iter()
            .find(|p| p.kind == PartitionKind::Data)
            .map(span_of)
            .ok_or_else(|| Error::UnsupportedDisc("no data partition found on disc".into()))?;

        // Extract the game partition's ticket / tmd / cert chain for rvlt.* files.
        let mut partition = disc.open_partition_kind(PartitionKind::Data)?;
        let meta = partition.meta()?;
        let raw_ticket = meta
            .raw_ticket
            .as_ref()
            .ok_or_else(|| Error::UnsupportedDisc("partition has no ticket".into()))?
            .to_vec();
        let raw_tmd = meta
            .raw_tmd
            .as_ref()
            .ok_or_else(|| Error::UnsupportedDisc("partition has no TMD".into()))?
            .to_vec();
        Ok(SourceDisc {
            disc,
            path,
            game_id,
            disc_size,
            data_partition,
            partitions,
            raw_ticket,
            raw_tmd,
        })
    }

    /// The 6-character game ID (e.g. `RSPE01`).
    pub fn game_id(&self) -> [u8; 6] {
        self.game_id
    }

    /// The 6-character game ID as a string.
    pub fn game_id_str(&self) -> String {
        String::from_utf8_lossy(&self.game_id).into_owned()
    }

    /// The 4-character disc ID used to derive the Wii U title ID (first 4 game-id bytes).
    pub fn disc_id4(&self) -> [u8; 4] {
        [
            self.game_id[0],
            self.game_id[1],
            self.game_id[2],
            self.game_id[3],
        ]
    }

    /// The logical disc size in bytes.
    pub fn disc_size(&self) -> u64 {
        self.disc_size
    }

    /// The data partition's sector span.
    pub fn data_partition(&self) -> PartitionSpan {
        self.data_partition
    }

    /// Every partition's sector span, sorted ascending by start sector.
    pub fn partitions(&self) -> &[PartitionSpan] {
        &self.partitions
    }

    /// The game partition ticket bytes (`code/rvlt.tik`).
    pub fn raw_ticket(&self) -> &[u8] {
        &self.raw_ticket
    }

    /// The game partition TMD bytes (`code/rvlt.tmd`).
    pub fn raw_tmd(&self) -> &[u8] {
        &self.raw_tmd
    }

    /// The path the disc was opened from.
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Logical clusters in the data partition's data region.
    fn data_region_clusters(&self) -> u64 {
        (self.data_partition.data_end_sector - self.data_partition.data_start_sector) as u64
    }

    /// Logical (hash-stripped) byte size of the data partition's data region — the address space
    /// [`SourceDisc::open_data_partition`] reads span.
    fn data_region_size(&self) -> u64 {
        self.data_region_clusters() * LOG_CLUSTER
    }

    /// Open the data partition for logical (hash-stripped) reads.
    pub fn open_data_partition(&self) -> Result<Box<dyn nod::PartitionBase>> {
        Ok(self.disc.open_partition_kind(PartitionKind::Data)?)
    }

    /// The (valid) H3 table for the partition with `nod` index `index`.
    ///
    /// `nod` reads it from the partition header, so it is correct even for RVZ/WIA inputs that
    /// zero the per-cluster hash blocks — [`crate::disc_patch`] uses it as the base H3 table when
    /// rebuilding those blocks.
    pub fn partition_h3_table(&self, index: usize) -> Result<Vec<u8>> {
        let mut part = self.disc.open_partition(index)?;
        let meta = part.meta()?;
        meta.raw_h3_table
            .as_ref()
            .map(|v| v.to_vec())
            .ok_or_else(|| Error::UnsupportedDisc(format!("partition {index} has no H3 table")))
    }

    /// Read the data partition's `main.dol` (executable) and its logical offset.
    ///
    /// The offset is read from `boot.bin` (`0x420`, stored `>> 2`); the size is derived from
    /// the DOL header's 18 sections. Both are in the partition's logical (hash-stripped) data
    /// address space, which [`crate::disc_patch`] maps back to physical clusters.
    pub fn read_main_dol(&self) -> Result<MainDol> {
        let ioerr = |e| Error::io("<partition>", e);
        let mut part = self.disc.open_partition_kind(PartitionKind::Data)?;

        let mut boot = [0u8; 0x440];
        part.seek(SeekFrom::Start(0)).map_err(ioerr)?;
        part.read_exact(&mut boot).map_err(ioerr)?;
        let dol_off = (be32(&boot[0x420..]) as u64) << 2;

        let mut header = [0u8; 0x100];
        part.seek(SeekFrom::Start(dol_off)).map_err(ioerr)?;
        part.read_exact(&mut header).map_err(ioerr)?;
        // Bound the allocation on the header's (attacker-controlled) section table before making
        // it: each section against MAX_DOL_SIZE, then the whole DOL against the data region.
        let size = dol_size_from_header(&header, MAX_DOL_SIZE)?;
        let data_size = self.data_region_size();
        if dol_off.saturating_add(size) > data_size {
            return Err(Error::UnsupportedDisc(format!(
                "main.dol at offset {dol_off} is {size} bytes, past the end of the \
                 {data_size}-byte partition data region"
            )));
        }

        let mut data = vec![0u8; size as usize];
        part.seek(SeekFrom::Start(dol_off)).map_err(ioerr)?;
        part.read_exact(&mut data).map_err(ioerr)?;
        Ok(MainDol {
            offset: dol_off,
            data,
        })
    }

    /// Mutable access to the underlying decrypted disc stream (`Read + Seek`).
    ///
    /// Reading yields the full logical disc image with partition data decrypted and hash
    /// blocks intact; sectors outside partitions are raw disc bytes.
    pub fn stream(&mut self) -> &mut Disc {
        &mut self.disc
    }

    /// Runs of 64-cluster hash groups (in the data partition) to store in the NFS, as
    /// `(first_group, num_groups)`.
    ///
    /// The base set is the boot structures (boot.bin/bi2/apploader/main.dol/FST) plus every FST
    /// file. Two controls adjust it:
    ///
    /// * `skip_gaps` (normally `true`): drop the inter-file "gaps" the game never reads. A Wii disc
    ///   pads gaps with non-zero garbage, so only the FST — not a zero-scan — can tell real data
    ///   from padding. With `skip_gaps == false` every group is stored (the whole partition).
    /// * `trim_zeros` (normally `false`): additionally drop the groups that lie **fully inside an
    ///   FST file whose entire content is zero** (e.g. large dummy/padding files). The data
    ///   reconstructs as zeros on read, but — exactly like a skipped gap — a trimmed group has no
    ///   stored hash blocks, so it is *not* hash-valid if read (a validating reader reports a bad H0
    ///   hash). This is safe only because such filler files are never read; hence it is opt-in. A
    ///   group that only partly overlaps a zero file (sharing a boundary with real data or gap
    ///   garbage) is kept, since it is not all-zero.
    ///
    /// A boot structure or FST entry reaching past the end of the data region is a corrupt disc and
    /// is rejected, identically with and without `trim_zeros`.
    pub fn used_data_group_runs(
        &self,
        skip_gaps: bool,
        trim_zeros: bool,
    ) -> Result<Vec<(u32, u32)>> {
        let clusters = self.data_region_clusters();
        let data_size = self.data_region_size();

        let mut part = self.open_data_partition()?;
        let ioerr = |e| Error::io("<partition>", e);

        // boot.bin: main.dol and FST offsets (all logical, stored >> 2).
        let mut boot = [0u8; 0x440];
        part.seek(SeekFrom::Start(0)).map_err(ioerr)?;
        part.read_exact(&mut boot).map_err(ioerr)?;
        let dol_off = (be32(&boot[0x420..]) as u64) << 2;
        let fst_off = (be32(&boot[0x424..]) as u64) << 2;
        let fst_size = (be32(&boot[0x428..]) as u64) << 2;

        // apploader (logical 0x2440): header 0x20, then image + trailer.
        let mut ap = [0u8; 0x20];
        part.seek(SeekFrom::Start(0x2440)).map_err(ioerr)?;
        part.read_exact(&mut ap).map_err(ioerr)?;
        let ap_end = 0x2440 + 0x20 + be32(&ap[0x14..]) as u64 + be32(&ap[0x18..]) as u64;

        // main.dol size (18 sections, offsets at 0x00.., sizes at 0x90..).
        let mut dolh = [0u8; 0x100];
        part.seek(SeekFrom::Start(dol_off)).map_err(ioerr)?;
        part.read_exact(&mut dolh).map_err(ioerr)?;
        let dol_size = dol_size_from_header(&dolh, MAX_DOL_SIZE)?;

        // The boot structures (regardless of on-disc order), then every file in the FST. Collected
        // rather than marked inline so zero-trim candidates can be re-read once the FST's borrow on
        // `part` ends, and so the marking itself is pure (see `plan_group_runs`).
        let mut extents: Vec<(u64, u64)> = vec![
            (0, ap_end), // boot.bin + bi2 + apploader
            (dol_off, dol_size),
            (fst_off, fst_size),
        ];
        let mut files: Vec<(u64, u64)> = Vec::new();
        {
            let meta = part.meta()?;
            let fst = meta
                .fst()
                .map_err(|e| Error::UnsupportedDisc(format!("partition has no FST: {e}")))?;
            for (_, node, _) in fst.iter() {
                if node.is_dir() {
                    continue;
                }
                files.push((node.offset(true), node.length()));
            }
        }
        extents.extend_from_slice(&files);

        // Bounds-check every extent before scanning anything, so a corrupt entry reports the same
        // descriptive error with and without `trim_zeros` (the scan below would otherwise hit it
        // first and fail with a bare short read). `plan_group_runs` re-checks; this only fixes
        // *which* error a corrupt disc gets.
        for &(off, len) in &extents {
            let _ = extent_groups(off, len, data_size)?;
        }

        // Zero-fill trimming: find the wholly-zero FST files whose contained groups can be dropped.
        let mut zero_extents: Vec<(u64, u64)> = Vec::new();
        if trim_zeros {
            for &(off, len) in &files {
                if zero_trim_groups(off, len).is_none() {
                    continue;
                }
                if region_is_zero(part.as_mut(), off, len).map_err(ioerr)? {
                    zero_extents.push((off, len));
                }
            }
        }

        plan_group_runs(&extents, clusters, skip_gaps, &zero_extents)
    }
}

impl DecryptedDisc for SourceDisc {
    fn disc_size(&self) -> u64 {
        self.disc_size
    }

    fn disc_stream(&mut self) -> &mut dyn ReadSeek {
        &mut self.disc
    }
}

/// Which console an input image is for.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DiscKind {
    /// A Wii disc (injected directly; see [`SourceDisc`]).
    Wii,
    /// A GameCube disc (injected via Nintendont; see [`GcImage`]).
    GameCube,
}

/// Peek at an input image and report whether it is a Wii or GameCube disc, so the pipeline can
/// pick the right path. Reads only the disc header.
pub fn probe(path: impl AsRef<Path>) -> Result<DiscKind> {
    let options = OpenOptions {
        rebuild_encryption: false,
        ..Default::default()
    };
    let disc = Disc::new_with_options(path.as_ref(), &options)?;
    let header = disc.header();
    if header.is_wii() {
        Ok(DiscKind::Wii)
    } else if header.is_gamecube() {
        Ok(DiscKind::GameCube)
    } else {
        Err(Error::UnsupportedDisc(format!(
            "'{}' is neither a Wii nor a GameCube disc",
            path.as_ref().display()
        )))
    }
}

/// A source GameCube disc image opened for reading.
///
/// Unlike a Wii disc, a GameCube image has no partitions, encryption, hash tree, or ticket/TMD —
/// it is a plain 1:1 disc image. `nod` transparently decompresses/reconstructs the container
/// (ISO/GCM/CISO/NKit/GCZ/RVZ) to its logical full-size bytes, which we embed verbatim as
/// `files/game.iso` inside the synthetic Wii disc that boots Nintendont (see `crate::wii_author`).
pub struct GcImage {
    disc: Disc,
    path: PathBuf,
    game_id: [u8; 6],
    iso_size: u64,
}

impl GcImage {
    /// Open a GameCube disc image. Errors if the image is not a GameCube disc.
    pub fn open(path: impl AsRef<Path>) -> Result<Self> {
        let path = path.as_ref().to_path_buf();
        let options = OpenOptions {
            rebuild_encryption: false,
            ..Default::default()
        };
        let disc = Disc::new_with_options(&path, &options)?;

        let header = disc.header();
        if !header.is_gamecube() {
            return Err(Error::UnsupportedDisc(format!(
                "'{}' is not a GameCube disc",
                path.display()
            )));
        }
        let mut game_id = [0u8; 6];
        game_id.copy_from_slice(&header.game_id);
        let iso_size = disc.disc_size();

        Ok(GcImage {
            disc,
            path,
            game_id,
            iso_size,
        })
    }

    /// The 6-character game ID (e.g. `GM2E8P`).
    pub fn game_id(&self) -> [u8; 6] {
        self.game_id
    }

    /// The 6-character game ID as a string.
    pub fn game_id_str(&self) -> String {
        String::from_utf8_lossy(&self.game_id).into_owned()
    }

    /// The 4-character disc ID used to derive the Wii U title ID (first 4 game-id bytes).
    pub fn disc_id4(&self) -> [u8; 4] {
        [
            self.game_id[0],
            self.game_id[1],
            self.game_id[2],
            self.game_id[3],
        ]
    }

    /// The region code character (4th game-id byte: `E`=NTSC-U, `P`=PAL, `J`=NTSC-J, …).
    pub fn region_char(&self) -> u8 {
        self.game_id[3]
    }

    /// The logical full-size ISO length in bytes.
    pub fn iso_size(&self) -> u64 {
        self.iso_size
    }

    /// The path the image was opened from.
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// The decrypted, reconstructed logical ISO byte stream (`Read + Seek`), covering
    /// `0..iso_size()`.
    pub fn iso_stream(&mut self) -> &mut dyn ReadSeek {
        &mut self.disc
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Verify GameCube ingestion against a real image: probe reports GameCube, the game id and
    /// logical size are sane, and the first bytes are the game id (GameCube images have no magic
    /// word at 0x00 — the id sits there). Uses `test_titles/Super Monkey Ball 2 (USA).rvz`.
    #[test]
    #[ignore = "reads a GameCube test image; run manually with the test title present"]
    fn opens_gamecube_test_image() {
        let title = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../test_titles/Super Monkey Ball 2 (USA).rvz");
        if !title.exists() {
            eprintln!(
                "skipping opens_gamecube_test_image: {} not present",
                title.display()
            );
            return;
        }

        assert_eq!(probe(&title).unwrap(), DiscKind::GameCube);

        let mut gc = GcImage::open(&title).unwrap();
        let id = gc.game_id_str();
        eprintln!("game id = {id}, iso size = {} bytes", gc.iso_size());
        assert_eq!(id.len(), 6);
        // Super Monkey Ball 2 (USA) is GM2E8P.
        assert!(id.starts_with("GM2E"), "unexpected game id {id}");
        assert_eq!(gc.disc_id4(), *b"GM2E");
        assert_eq!(gc.region_char(), b'E');
        // A standard single-layer GameCube disc is 1,459,978,240 bytes.
        assert_eq!(gc.iso_size(), 1_459_978_240);

        // The logical stream starts with the game id at offset 0.
        let mut head = [0u8; 6];
        gc.iso_stream().seek(SeekFrom::Start(0)).unwrap();
        gc.iso_stream().read_exact(&mut head).unwrap();
        assert_eq!(&head, gc.game_id().as_slice());
    }

    #[test]
    fn region_is_zero_detects_zero_and_nonzero() {
        use std::io::Cursor;
        // All zero over more than one read chunk boundary is still zero.
        let zeros = vec![0u8; (1 << 20) + 4096];
        assert!(region_is_zero(&mut Cursor::new(zeros), 0, (1 << 20) + 4096).unwrap());
        // A single non-zero byte makes the region non-zero.
        let mut one = vec![0u8; 4096];
        one[4000] = 1;
        assert!(!region_is_zero(&mut Cursor::new(one), 0, 4096).unwrap());
        // The offset is honoured: a non-zero prefix outside the range is ignored.
        let mut data = vec![0xFFu8; 100];
        data.extend(vec![0u8; 200]);
        assert!(region_is_zero(&mut Cursor::new(data.clone()), 100, 200).unwrap());
        assert!(!region_is_zero(&mut Cursor::new(data), 0, 300).unwrap());
    }

    /// Logical bytes per hash group, spelled out the way the pre-refactor code did.
    const GB: u64 = 64 * 0x7C00;

    /// A 10-group data region (640 clusters), the size most planner tests work in.
    const TEN_GROUPS: u64 = 640;

    /// Build a DOL header from `(offset, size)` section pairs (offsets at `0x00..`, sizes at
    /// `0x90..`); unlisted sections stay zero.
    fn dol_header(sections: &[(u32, u32)]) -> [u8; 0x100] {
        let mut h = [0u8; 0x100];
        for (i, &(off, sz)) in sections.iter().enumerate() {
            h[i * 4..i * 4 + 4].copy_from_slice(&off.to_be_bytes());
            h[0x90 + i * 4..0x90 + i * 4 + 4].copy_from_slice(&sz.to_be_bytes());
        }
        h
    }

    /// Runs merge only across *strictly* adjacent groups; any gap, however small, splits them.
    #[test]
    fn plan_group_runs_coalesces_only_strictly_adjacent_groups() {
        // One byte in each of groups 0, 1, 3 and 9 (of 10).
        let extents = [(0, 1), (GB, 1), (3 * GB, 1), (9 * GB, 1)];
        let runs = plan_group_runs(&extents, TEN_GROUPS, true, &[]).unwrap();
        assert_eq!(runs, vec![(0, 2), (3, 1), (9, 1)]);
    }

    /// An extent marks every group it touches, including the partial groups at both ends.
    #[test]
    fn plan_group_runs_marks_every_group_an_extent_spans() {
        // Starts halfway through group 0 and ends halfway through group 3 → groups 0..=3.
        let runs = plan_group_runs(&[(GB / 2, 3 * GB)], TEN_GROUPS, true, &[]).unwrap();
        assert_eq!(runs, vec![(0, 4)]);
        // A single byte straddling nothing still marks exactly its own group.
        let runs = plan_group_runs(&[(4 * GB - 1, 2)], TEN_GROUPS, true, &[]).unwrap();
        assert_eq!(runs, vec![(3, 2)]);
        // The whole region as one extent is one run covering every group.
        let runs = plan_group_runs(&[(0, 10 * GB)], TEN_GROUPS, true, &[]).unwrap();
        assert_eq!(runs, vec![(0, 10)]);
    }

    /// A data region whose cluster count is not a multiple of 64 still gets a (partial) final
    /// group: `ngroups = ceil(clusters / 64)`.
    #[test]
    fn plan_group_runs_handles_partial_final_group() {
        let clusters = 2 * 64 + 5; // 133 clusters → 3 groups, the last only 5 clusters wide
        let data_size = clusters * 0x7C00;
        // The very last readable byte lands in the partial group 2.
        let runs = plan_group_runs(&[(data_size - 1, 1)], clusters, true, &[]).unwrap();
        assert_eq!(runs, vec![(2, 1)]);
        // …and `skip_gaps == false` stores all three groups, partial one included.
        let runs = plan_group_runs(&[], clusters, false, &[]).unwrap();
        assert_eq!(runs, vec![(0, 3)]);
    }

    /// No extents (e.g. an empty FST) marks nothing at all — the current behaviour is an empty run
    /// list, not a whole-partition fallback.
    #[test]
    fn plan_group_runs_with_no_extents_yields_no_runs() {
        assert_eq!(plan_group_runs(&[], TEN_GROUPS, true, &[]).unwrap(), vec![]);
    }

    /// Zero-length FST entries mark nothing, and are exempt from the bounds check (their offset is
    /// meaningless), matching the pre-refactor `mark`'s early return.
    #[test]
    fn plan_group_runs_ignores_zero_length_extents() {
        let data_size = TEN_GROUPS * 0x7C00;
        let extents = [
            (0, 1),
            (5 * GB, 0),
            (data_size + 1_000_000, 0),
            (u64::MAX, 0),
        ];
        let runs = plan_group_runs(&extents, TEN_GROUPS, true, &[]).unwrap();
        assert_eq!(runs, vec![(0, 1)]);
    }

    /// `skip_gaps == false` stores every group regardless of the extents given.
    #[test]
    fn plan_group_runs_without_skip_gaps_stores_every_group() {
        let runs = plan_group_runs(&[(0, 1)], TEN_GROUPS, false, &[]).unwrap();
        assert_eq!(runs, vec![(0, 10)]);
        let runs = plan_group_runs(&[], TEN_GROUPS, false, &[]).unwrap();
        assert_eq!(runs, vec![(0, 10)]);
    }

    /// Zero-fill trimming is applied *after* the `skip_gaps` fill, so it punches holes even when
    /// gap-skipping is turned off.
    #[test]
    fn plan_group_runs_trim_applies_after_skip_gaps_fill() {
        let zero = [(0, 3 * GB)];
        let runs = plan_group_runs(&[], TEN_GROUPS, false, &zero).unwrap();
        assert_eq!(runs, vec![(3, 7)]);
    }

    /// Only whole groups inside a zero file are dropped; the boundary groups it shares with other
    /// data are kept.
    #[test]
    fn plan_group_runs_trims_only_fully_contained_zero_groups() {
        let extents = [(0, 10 * GB)];
        // Zero file from mid-group-0 to mid-group-4 → whole groups 1..4 dropped.
        let zero = [(GB / 2, 4 * GB)];
        let runs = plan_group_runs(&extents, TEN_GROUPS, true, &zero).unwrap();
        assert_eq!(runs, vec![(0, 1), (4, 6)]);
        // A group-aligned zero file drops exactly its own groups.
        let zero = [(2 * GB, 3 * GB)];
        let runs = plan_group_runs(&extents, TEN_GROUPS, true, &zero).unwrap();
        assert_eq!(runs, vec![(0, 2), (5, 5)]);
    }

    /// Zero files shorter than two whole groups are never trimmed, even when group-aligned and so
    /// nominally covering a whole group.
    #[test]
    fn plan_group_runs_ignores_zero_files_smaller_than_two_groups() {
        let extents = [(0, 10 * GB)];
        assert_eq!(zero_trim_groups(5 * GB, GB), None);
        let runs = plan_group_runs(&extents, TEN_GROUPS, true, &[(5 * GB, GB)]).unwrap();
        assert_eq!(runs, vec![(0, 10)]);
        // Two groups' worth is the threshold, and is trimmed.
        assert_eq!(zero_trim_groups(5 * GB, 2 * GB), Some(5..7));
        let runs = plan_group_runs(&extents, TEN_GROUPS, true, &[(5 * GB, 2 * GB)]).unwrap();
        assert_eq!(runs, vec![(0, 5), (7, 3)]);
    }

    /// Extents reaching past the data region are a corrupt disc and are rejected, rather than
    /// silently dropped (the old marking path) or failing with a short read (the old zero scan).
    #[test]
    fn plan_group_runs_rejects_extent_past_data_region() {
        let clusters = 2 * 64 + 5; // 133 clusters → 3 groups; group 2 is only 5 clusters wide
        let data_size = clusters * 0x7C00;

        // Ending exactly at the last byte is fine.
        assert!(plan_group_runs(&[(0, data_size)], clusters, true, &[]).is_ok());

        // One byte past the end is not.
        let err = plan_group_runs(&[(data_size - 1, 2)], clusters, true, &[])
            .unwrap_err()
            .to_string();
        assert!(err.contains(&(data_size - 1).to_string()), "{err}");
        assert!(err.contains(&data_size.to_string()), "{err}");

        // Starting past the end is rejected too, even though its cluster still falls inside the
        // final *partial* group (index 2 < 3) that the old code would have marked silently.
        assert!(plan_group_runs(&[(data_size, 1)], clusters, true, &[]).is_err());

        // An offset+length that overflows u64 errors instead of wrapping.
        assert!(plan_group_runs(&[(u64::MAX, 2)], clusters, true, &[]).is_err());
    }

    /// The DOL size is the largest section end, floored at the 0x100-byte header.
    #[test]
    fn dol_size_from_header_takes_largest_section_end() {
        assert_eq!(
            dol_size_from_header(&dol_header(&[]), MAX_DOL_SIZE).unwrap(),
            0x100
        );
        let h = dol_header(&[(0x100, 0x200), (0x2000, 0x40), (0x400, 0x10)]);
        assert_eq!(dol_size_from_header(&h, MAX_DOL_SIZE).unwrap(), 0x2040);
        // A section ending exactly at the limit is accepted.
        let h = dol_header(&[(0x100, 0xF00)]);
        assert_eq!(dol_size_from_header(&h, 0x1000).unwrap(), 0x1000);
    }

    /// A corrupt section table is rejected before it can drive a multi-gigabyte allocation.
    #[test]
    fn dol_size_from_header_rejects_oversized_sections() {
        let h = dol_header(&[(0x100, 0x200), (u32::MAX, u32::MAX)]);
        let err = dol_size_from_header(&h, MAX_DOL_SIZE)
            .unwrap_err()
            .to_string();
        assert!(err.contains("section 1"), "{err}");
        assert!(err.contains(&MAX_DOL_SIZE.to_string()), "{err}");
        // Just one byte over is enough.
        let h = dol_header(&[(0x100, 0xF01)]);
        assert!(dol_size_from_header(&h, 0x1000).is_err());
    }

    #[test]
    fn fully_contained_groups_excludes_boundary_groups() {
        let gb = 64 * 0x7C00u64; // logical bytes per hash group
                                 // Group-aligned file of exactly 3 groups: all three are fully contained.
        assert_eq!(fully_contained_groups(0, 3 * gb, gb), 0..3);
        // Offset mid-group: the partial leading and trailing groups are excluded.
        assert_eq!(fully_contained_groups(gb / 2, 3 * gb, gb), 1..3);
        // A file smaller than a whole group contains none.
        let r = fully_contained_groups(gb / 2, gb / 4, gb);
        assert!(r.end <= r.start, "expected empty, got {r:?}");
        // Exactly one group, aligned.
        assert_eq!(fully_contained_groups(5 * gb, gb, gb), 5..6);
    }
}
