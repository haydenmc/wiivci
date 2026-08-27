//! Wii U Virtual Console NFS encoder.
//!
//! Converts a decrypted Wii disc (see [`crate::input`]) into the `hif_%06d.nfs` files a Wii
//! U VC title mounts as its game disc. The stored data is the logical disc image with the
//! game partition decrypted (hash blocks intact), packed sparsely via an LBA-range table,
//! then AES-128-CBC encrypted per sector with the base title's `htk.bin` key.
//!
//! Correctness is anchored by the `nod` NFS *reader*: anything this encoder writes can be
//! read back by `nod` to the exact decrypted disc it started from (see the round-trip test).

pub mod crypto;
pub mod eggs;
pub mod split;

use std::io::{Read, Seek, SeekFrom};
use std::path::Path;

use crate::disc_patch::{apply_edits_to_group, recompute_group, DiscPlan, PartitionPlan};
use crate::error::{Error, Result};
use crate::input::{DecryptedDisc, DISC_SECTOR_SIZE};
use eggs::{EggsHeader, LbaRange};
use split::SplitWriter;

/// Clusters per Wii hash group (must match [`crate::disc_patch`]).
const SECTORS_PER_GROUP: usize = 64;

/// Bytes of file data per cluster: the 0x8000 cluster minus its 0x400 hash block (must match
/// `crate::disc_patch`'s `DATA`). [`PartitionPlan::edits`] are keyed by this logical data offset,
/// unlike `disc_patches`/`header_patches`, which use absolute disc byte offsets.
const DATA_PER_SECTOR: u64 = DISC_SECTOR_SIZE as u64 - 0x400;

/// Outcome of an NFS build.
#[derive(Debug, Clone)]
pub struct NfsStats {
    /// Number of `hif_*.nfs` files written.
    pub file_count: u32,
    /// Total bytes written across all files (including the 0x200 header).
    pub total_bytes: u64,
    /// The LBA ranges written to the header.
    pub ranges: Vec<LbaRange>,
}

/// A contiguous run of 64-cluster hash groups within a partition's data region that holds real
/// (non-zero) data and must be stored.
#[derive(Clone, Copy, Debug)]
struct GroupRun {
    /// First hash group (0-based within the partition data region).
    first_group: u32,
    /// Number of consecutive groups.
    num_groups: u32,
}

/// The hash-group runs to store for a partition: the plan's FST-derived runs, or every group when
/// the plan lists none (the synthetic GC disc, which has no gaps).
fn group_runs(pp: &PartitionPlan) -> Vec<GroupRun> {
    if pp.stored_data_groups.is_empty() {
        let total = (pp.data_end_sector - pp.data_start_sector) as u64;
        let ngroups = total.div_ceil(SECTORS_PER_GROUP as u64) as u32;
        return vec![GroupRun {
            first_group: 0,
            num_groups: ngroups,
        }];
    }
    pp.stored_data_groups
        .iter()
        .map(|&(first_group, num_groups)| GroupRun {
            first_group,
            num_groups,
        })
        .collect()
}

/// The disc-level ranges present in every inject: the disc header and the partition table/region
/// info sectors.
fn disc_header_ranges() -> Vec<LbaRange> {
    vec![
        LbaRange {
            start_sector: 0,
            num_sectors: 1,
        },
        LbaRange {
            start_sector: 8,
            num_sectors: 2,
        },
    ]
}

/// Build the NFS files for `source` into `out_dir` using the 16-byte `htk` key.
///
/// `out_dir` must already exist. `plan` (from [`crate::disc_patch::plan_disc`]) drives the
/// per-partition Wii hash-tree rebuild — RVZ/WIA sources zero the per-cluster hash blocks, so
/// they are recomputed here — and any `main.dol` video patches.
///
/// The partition is stored **sparsely**: the pre-data header (ticket/TMD/cert/H3) plus only the
/// hash-group runs in `plan.partitions[].stored_data_groups`, skipping the (potentially multi-GB)
/// gaps between files. This keeps the NFS as small as a compacted disc while leaving every file at
/// its original offset. Which groups are stored is decided upstream in
/// [`crate::disc_patch::plan_disc`] via [`crate::input::SourceDisc::used_data_group_runs`] (FST
/// coverage, optional gap-skipping and wholly-zero-file trimming); an empty run list means "store
/// every group" (the synthetic GC disc).
pub fn build_nfs<D: DecryptedDisc + ?Sized>(
    source: &mut D,
    htk: &[u8; 16],
    out_dir: &Path,
    plan: &DiscPlan,
) -> Result<NfsStats> {
    let disc_size = source.disc_size();
    let disc = source.disc_stream();

    // Pass 1: work out the sparse group runs for each partition, and the full range table.
    let mut ranges = disc_header_ranges();
    let mut partition_runs: Vec<Vec<GroupRun>> = Vec::with_capacity(plan.partitions.len());
    for pp in &plan.partitions {
        // The partition header (ticket/TMD/cert/H3) is always stored.
        ranges.push(LbaRange {
            start_sector: pp.start_sector,
            num_sectors: pp.data_start_sector - pp.start_sector,
        });
        let total = pp.data_end_sector - pp.data_start_sector;
        let runs = group_runs(pp);
        for run in &runs {
            // Clamp to the partition end — the final hash group may be partial, and the EGGS range
            // must cover exactly the sectors written, no more.
            let first = run.first_group * SECTORS_PER_GROUP as u32;
            let last = ((run.first_group + run.num_groups) * SECTORS_PER_GROUP as u32).min(total);
            ranges.push(LbaRange {
                start_sector: pp.data_start_sector + first,
                num_sectors: last - first,
            });
        }
        partition_runs.push(runs);
    }

    // Every planned patch must land in a region we are about to write — check before writing a
    // single byte, or a dropped patch ships as a silently wrong build (see the fn docs).
    verify_patches_contained(plan, &partition_runs)?;

    let header = EggsHeader::new(ranges)?;

    // Pass 2: write the header then every range, in order.
    let mut writer = SplitWriter::new(out_dir)?;
    writer.write_all(&header.to_bytes())?;
    let mut sector = vec![0u8; DISC_SECTOR_SIZE];

    // Disc header / partition table, with the disc-level patches (rewritten partition table).
    for range in disc_header_ranges() {
        for s in range.start_sector..range.start_sector + range.num_sectors {
            let sec_start = s as u64 * DISC_SECTOR_SIZE as u64;
            read_sector(disc, sec_start, disc_size, &mut sector)?;
            for (off, bytes) in &plan.disc_patches {
                splice(&mut sector, sec_start, *off, bytes);
            }
            crypto::encrypt_sector(htk, s, &mut sector);
            writer.write_all(&sector)?;
        }
    }

    for (pp, runs) in plan.partitions.iter().zip(&partition_runs) {
        write_partition(&mut writer, disc, htk, pp, disc_size, runs)?;
    }

    let total_bytes = writer.total_written();
    let file_count = writer.finish()?;
    Ok(NfsStats {
        file_count,
        total_bytes,
        ranges: header.ranges().to_vec(),
    })
}

/// Check that every planned patch lands somewhere the NFS actually writes.
///
/// [`splice`] silently no-ops when a patch does not overlap the sector being written, and hash
/// groups outside the stored runs are never materialized at all. A planned patch that falls
/// outside every written region is therefore dropped without a trace and the build "succeeds"
/// with wrong bytes — and these patches are exactly the ones that must not go missing (the
/// rewritten partition table, the in-disc ticket/TMD fakesign, the rebuilt H3 table, the
/// `main.dol` video patches). Run after the range table is known and before the first write.
///
/// Addressing note: `disc_patches` and `header_patches` are keyed by **absolute disc byte
/// offset**, `edits` by **logical partition-data offset** (hash blocks excluded), matching how
/// [`build_nfs`]/[`write_partition`] feed them to [`splice`] and
/// [`crate::disc_patch::apply_edits_to_group`].
fn verify_patches_contained(plan: &DiscPlan, partition_runs: &[Vec<GroupRun>]) -> Result<()> {
    let sector_bytes = DISC_SECTOR_SIZE as u64;

    // Disc-level patches: only the sectors of `disc_header_ranges()` are written at disc level.
    for (off, bytes) in &plan.disc_patches {
        if bytes.is_empty() {
            continue;
        }
        let end = off.saturating_add(bytes.len() as u64);
        let contained = disc_header_ranges().iter().any(|r| {
            let start = r.start_sector as u64 * sector_bytes;
            *off >= start && end <= start + r.num_sectors as u64 * sector_bytes
        });
        if !contained {
            return Err(Error::FormatLimit(format!(
                "disc patch at 0x{off:X}..0x{end:X} lies outside the disc-level sectors the NFS \
                 writes, so it would be silently dropped"
            )));
        }
    }

    for (i, (pp, runs)) in plan.partitions.iter().zip(partition_runs).enumerate() {
        // Header patches: the pre-data header region [start_sector, data_start_sector).
        let hdr_start = pp.start_sector as u64 * sector_bytes;
        let hdr_end = pp.data_start_sector as u64 * sector_bytes;
        for (off, bytes) in &pp.header_patches {
            if bytes.is_empty() {
                continue;
            }
            let end = off.saturating_add(bytes.len() as u64);
            if *off < hdr_start || end > hdr_end {
                return Err(Error::FormatLimit(format!(
                    "partition {i} header patch at 0x{off:X}..0x{end:X} lies outside its stored \
                     header region 0x{hdr_start:X}..0x{hdr_end:X}, so it would be silently dropped"
                )));
            }
        }

        // Edits: every hash group they touch must be one this partition stores.
        for (off, bytes) in &pp.edits {
            if bytes.is_empty() {
                continue;
            }
            let last_byte = off.saturating_add(bytes.len() as u64 - 1);
            let first_group = off / DATA_PER_SECTOR / SECTORS_PER_GROUP as u64;
            let last_group = last_byte / DATA_PER_SECTOR / SECTORS_PER_GROUP as u64;
            for g in first_group..=last_group {
                let stored = runs.iter().any(|r| {
                    g >= r.first_group as u64 && g < r.first_group as u64 + r.num_groups as u64
                });
                if !stored {
                    return Err(Error::FormatLimit(format!(
                        "partition {i} edit at logical offset 0x{off:X} ({} bytes) touches hash \
                         group {g}, which the NFS does not store, so it would be silently dropped",
                        bytes.len()
                    )));
                }
            }
        }
    }
    Ok(())
}

/// Write one partition: its pre-data header region verbatim (with `header_patches` spliced in),
/// then only the hash-group `runs` that hold real data, with the Wii hash tree rebuilt group-by-
/// group and `main.dol` edits applied.
fn write_partition<R: Read + Seek + ?Sized>(
    writer: &mut SplitWriter,
    disc: &mut R,
    htk: &[u8; 16],
    pp: &PartitionPlan,
    disc_size: u64,
    runs: &[GroupRun],
) -> Result<()> {
    let mut sector = vec![0u8; DISC_SECTOR_SIZE];

    // Pre-data header region (ticket/TMD/cert/H3 table), verbatim + patches.
    for s in pp.start_sector..pp.data_start_sector {
        let sec_start = s as u64 * DISC_SECTOR_SIZE as u64;
        read_sector(disc, sec_start, disc_size, &mut sector)?;
        for (off, bytes) in &pp.header_patches {
            splice(&mut sector, sec_start, *off, bytes);
        }
        crypto::encrypt_sector(htk, s, &mut sector);
        writer.write_all(&sector)?;
    }

    // Stored cluster region: rebuild the hash tree one 64-cluster group at a time, but only for
    // the groups in `runs` (the rest are implicit zeros the emulator never reads).
    let total = (pp.data_end_sector - pp.data_start_sector) as u64;
    let mut clusters = vec![[0u8; DISC_SECTOR_SIZE]; SECTORS_PER_GROUP];
    for run in runs {
        for g in run.first_group..run.first_group + run.num_groups {
            for (k, cluster) in clusters.iter_mut().enumerate() {
                let ps = g as u64 * SECTORS_PER_GROUP as u64 + k as u64;
                if ps < total {
                    let off = (pp.data_start_sector as u64 + ps) * DISC_SECTOR_SIZE as u64;
                    read_sector(disc, off, disc_size, cluster)?;
                } else {
                    cluster.fill(0);
                }
            }
            apply_edits_to_group(&mut clusters, g, &pp.edits);
            recompute_group(&mut clusters)?;
            for (k, cluster) in clusters.iter_mut().enumerate() {
                let ps = g as u64 * SECTORS_PER_GROUP as u64 + k as u64;
                if ps < total {
                    let s = pp.data_start_sector + ps as u32;
                    crypto::encrypt_sector(htk, s, cluster);
                    writer.write_all(cluster)?;
                }
            }
        }
    }
    Ok(())
}

/// Overlay `bytes` (which live at absolute disc offset `patch_off`) onto `sector`, whose first
/// byte is at absolute disc offset `sec_start`. No-op if they do not overlap.
fn splice(sector: &mut [u8], sec_start: u64, patch_off: u64, bytes: &[u8]) {
    let sec_end = sec_start + sector.len() as u64;
    let p_end = patch_off + bytes.len() as u64;
    let ov_start = sec_start.max(patch_off);
    let ov_end = sec_end.min(p_end);
    if ov_start < ov_end {
        let dst = (ov_start - sec_start) as usize;
        let src = (ov_start - patch_off) as usize;
        let len = (ov_end - ov_start) as usize;
        sector[dst..dst + len].copy_from_slice(&bytes[src..src + len]);
    }
}

/// Read one 0x8000 sector at `offset` from the decrypted disc, zero-padding a short/OOB read.
fn read_sector<R: Read + Seek + ?Sized>(
    disc: &mut R,
    offset: u64,
    disc_size: u64,
    out: &mut [u8],
) -> Result<()> {
    out.fill(0);
    if offset >= disc_size {
        return Ok(());
    }
    disc.seek(SeekFrom::Start(offset))
        .map_err(|e| Error::io("<disc>", e))?;
    let to_read = ((disc_size - offset) as usize).min(out.len());
    disc.read_exact(&mut out[..to_read])
        .map_err(|e| Error::io("<disc>", e))?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::input::SourceDisc;

    const SEC: u64 = DISC_SECTOR_SIZE as u64;

    // ---- splice ---------------------------------------------------------------------------

    #[test]
    fn splice_writes_patch_fully_inside_sector() {
        let mut sector = vec![0u8; DISC_SECTOR_SIZE];
        splice(&mut sector, SEC, SEC + 0x10, &[1, 2, 3, 4]);
        assert_eq!(&sector[0x10..0x14], &[1, 2, 3, 4]);
        assert!(sector[..0x10].iter().all(|&b| b == 0));
        assert!(sector[0x14..].iter().all(|&b| b == 0));
    }

    #[test]
    fn splice_clips_patch_overlapping_sector_head_and_tail() {
        // Patch starts before the sector: only its tail lands, at offset 0.
        let mut sector = vec![0u8; DISC_SECTOR_SIZE];
        splice(&mut sector, SEC, SEC - 2, &[1, 2, 3, 4]);
        assert_eq!(&sector[..2], &[3, 4]);
        assert!(sector[2..].iter().all(|&b| b == 0));

        // Patch runs past the sector end: only its head lands, at the end of the sector.
        let mut sector = vec![0u8; DISC_SECTOR_SIZE];
        splice(&mut sector, SEC, 2 * SEC - 2, &[1, 2, 3, 4]);
        assert_eq!(&sector[DISC_SECTOR_SIZE - 2..], &[1, 2]);
        assert!(sector[..DISC_SECTOR_SIZE - 2].iter().all(|&b| b == 0));
    }

    /// The silent no-op at the heart of the dropped-patch bug: a patch that misses the sector
    /// leaves the buffer completely untouched, with no signal to the caller. This is why
    /// [`verify_patches_contained`] exists.
    #[test]
    fn splice_ignores_patch_outside_sector() {
        let mut sector = vec![0xAAu8; DISC_SECTOR_SIZE];
        splice(&mut sector, SEC, 0, &[1, 2, 3, 4]); // entirely before
        splice(&mut sector, SEC, SEC - 4, &[1, 2, 3, 4]); // ends exactly at sector start
        splice(&mut sector, SEC, 2 * SEC, &[1, 2, 3, 4]); // starts exactly at sector end
        splice(&mut sector, SEC, 9 * SEC, &[1, 2, 3, 4]); // entirely after
        assert!(
            sector.iter().all(|&b| b == 0xAA),
            "buffer must be untouched"
        );
    }

    #[test]
    fn splice_reassembles_patch_spanning_a_sector_boundary() {
        let patch = [1u8, 2, 3, 4];
        let patch_off = SEC - 2; // straddles sectors 0 and 1
        let mut sector0 = vec![0u8; DISC_SECTOR_SIZE];
        let mut sector1 = vec![0u8; DISC_SECTOR_SIZE];
        splice(&mut sector0, 0, patch_off, &patch);
        splice(&mut sector1, SEC, patch_off, &patch);
        assert_eq!(&sector0[DISC_SECTOR_SIZE - 2..], &[1, 2]);
        assert_eq!(&sector1[..2], &[3, 4]);
    }

    // ---- read_sector ----------------------------------------------------------------------

    #[test]
    fn read_sector_zero_pads_past_disc_end() {
        let disc_size = SEC + 0x100;
        let data: Vec<u8> = (0..disc_size).map(|i| i as u8).collect();
        let mut disc = std::io::Cursor::new(data.clone());
        let mut out = vec![0xFFu8; DISC_SECTOR_SIZE];

        read_sector(&mut disc, SEC, disc_size, &mut out).unwrap();
        assert_eq!(&out[..0x100], &data[SEC as usize..]);
        assert!(
            out[0x100..].iter().all(|&b| b == 0),
            "the tail past disc_size must be zero-padded"
        );
    }

    #[test]
    fn read_sector_wholly_past_disc_end_is_all_zeros() {
        let disc_size = SEC;
        let mut disc = std::io::Cursor::new(vec![0xABu8; disc_size as usize]);
        let mut out = vec![0xFFu8; DISC_SECTOR_SIZE];
        read_sector(&mut disc, disc_size, disc_size, &mut out).unwrap();
        assert!(out.iter().all(|&b| b == 0));
    }

    // ---- group_runs -----------------------------------------------------------------------

    fn test_partition(stored_data_groups: Vec<(u32, u32)>) -> PartitionPlan {
        PartitionPlan {
            start_sector: 0x20,
            data_start_sector: 0x24,
            data_end_sector: 0x24 + 4 * SECTORS_PER_GROUP as u32,
            header_patches: Vec::new(),
            edits: Vec::new(),
            stored_data_groups,
        }
    }

    #[test]
    fn group_runs_empty_plan_stores_every_group_rounding_the_tail_up() {
        let mut pp = test_partition(Vec::new());
        // 129 sectors = two full groups plus a one-sector tail group.
        pp.data_end_sector = pp.data_start_sector + 129;
        let runs = group_runs(&pp);
        assert_eq!(runs.len(), 1);
        assert_eq!(runs[0].first_group, 0);
        assert_eq!(runs[0].num_groups, 3, "the partial tail group is included");
    }

    #[test]
    fn group_runs_passes_plan_runs_through_unclamped() {
        let pp = test_partition(vec![(0, 1), (3, 2)]);
        let runs = group_runs(&pp);
        let pairs: Vec<(u32, u32)> = runs.iter().map(|r| (r.first_group, r.num_groups)).collect();
        // Verbatim, including a run whose last group runs past `data_end_sector`; build_nfs
        // clamps the *EGGS range* to the partition end rather than the run itself.
        assert_eq!(pairs, vec![(0, 1), (3, 2)]);
    }

    // ---- verify_patches_contained ---------------------------------------------------------

    fn test_plan(pp: PartitionPlan, disc_patches: Vec<(u64, Vec<u8>)>) -> DiscPlan {
        DiscPlan {
            partitions: vec![pp],
            disc_patches,
            rvlt_content_hash: None,
            applied: Vec::new(),
        }
    }

    fn check(plan: &DiscPlan) -> Result<()> {
        let runs: Vec<Vec<GroupRun>> = plan.partitions.iter().map(group_runs).collect();
        verify_patches_contained(plan, &runs)
    }

    #[test]
    fn verify_accepts_a_well_formed_plan() {
        let mut pp = test_partition(vec![(0, 2)]);
        // Header patch inside [0x20, 0x24) sectors, edit inside stored group 0.
        pp.header_patches = vec![(0x20 * SEC + 0x100, vec![0u8; 0x100])];
        pp.edits = vec![(0x1234, vec![0xAA; 16])];
        // Disc patch in the partition-table sectors {8, 9}.
        let plan = test_plan(pp, vec![(8 * SEC + 0x20, vec![0u8; 8])]);
        check(&plan).unwrap();
    }

    #[test]
    fn verify_rejects_disc_patch_outside_the_written_sectors() {
        // Sector 1 is not written at disc level (only {0} and {8, 9} are).
        let plan = test_plan(test_partition(vec![(0, 2)]), vec![(SEC, vec![0u8; 4])]);
        let err = check(&plan).unwrap_err().to_string();
        assert!(err.contains("disc patch"), "{err}");

        // Nor may a patch straddle the gap between the two disc-level ranges.
        let plan = test_plan(test_partition(vec![(0, 2)]), vec![(SEC - 2, vec![0u8; 4])]);
        assert!(check(&plan).is_err());

        // Or overrun the end of the last one.
        let plan = test_plan(
            test_partition(vec![(0, 2)]),
            vec![(10 * SEC - 2, vec![0u8; 4])],
        );
        assert!(check(&plan).is_err());
    }

    #[test]
    fn verify_rejects_header_patch_outside_the_partition_header() {
        // Before the partition start.
        let mut pp = test_partition(vec![(0, 2)]);
        pp.header_patches = vec![(0x1F * SEC, vec![0u8; 4])];
        let err = check(&test_plan(pp, Vec::new())).unwrap_err().to_string();
        assert!(err.contains("header patch"), "{err}");

        // Running past `data_start_sector` (into the cluster region, which is written from the
        // hash-group path and never sees `header_patches`).
        let mut pp = test_partition(vec![(0, 2)]);
        pp.header_patches = vec![(0x24 * SEC - 2, vec![0u8; 4])];
        assert!(check(&test_plan(pp, Vec::new())).is_err());
    }

    #[test]
    fn verify_rejects_edit_in_an_unstored_group() {
        // Groups 0 and 3 are stored; the edit lands in group 2.
        let mut pp = test_partition(vec![(0, 1), (3, 1)]);
        let off = 2 * SECTORS_PER_GROUP as u64 * DATA_PER_SECTOR;
        pp.edits = vec![(off, vec![0xAA; 4])];
        let err = check(&test_plan(pp, Vec::new())).unwrap_err().to_string();
        assert!(err.contains("hash group 2"), "{err}");
    }

    #[test]
    fn verify_rejects_edit_spilling_out_of_a_stored_group() {
        // Only group 0 is stored; the edit starts in its last data byte and spills into group 1.
        let mut pp = test_partition(vec![(0, 1)]);
        let group_data = SECTORS_PER_GROUP as u64 * DATA_PER_SECTOR;
        pp.edits = vec![(group_data - 1, vec![0xAA; 2])];
        let err = check(&test_plan(pp, Vec::new())).unwrap_err().to_string();
        assert!(err.contains("hash group 1"), "{err}");
    }

    #[test]
    fn verify_accepts_any_edit_when_the_plan_stores_every_group() {
        // Empty `stored_data_groups` is the store-everything fallback (synthetic GC disc).
        let mut pp = test_partition(Vec::new());
        let off = 3 * SECTORS_PER_GROUP as u64 * DATA_PER_SECTOR;
        pp.edits = vec![(off, vec![0xAA; 4])];
        check(&test_plan(pp, Vec::new())).unwrap();
    }

    /// End-to-end oracle: encode a real Wii disc to NFS (rebuilding the Wii hash tree and storing
    /// the data partition sparsely), then reopen it with `nod`'s hash **validation** enabled and
    /// confirm every FST **file** reads back byte-for-byte through the rebuilt hash tree. Reading a
    /// file exercises the stored (real-data) clusters' H0/H1/H2/H3 chain — the property a real VC
    /// checks. The inter-file gaps are intentionally not stored (sparse) and are never read, so a
    /// whole-partition compare would (correctly) differ there; we compare files instead.
    ///
    /// Uses `test_titles/Wii Sports (USA).rvz` if present; skipped otherwise. Ignored by
    /// default because it reads several GB — run with `cargo test --release -- --ignored`.
    #[test]
    #[ignore = "reads multi-GB disc; run manually with the test title present"]
    fn nfs_rebuilds_valid_wii_hashes() {
        use crate::disc_patch::plan_disc;
        use crate::video::VideoPatches;
        use std::collections::HashMap;
        use std::io::{Read, Seek, SeekFrom};

        let title = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../test_titles/Wii Sports (USA).rvz");
        if !title.exists() {
            eprintln!("skipping: {} not present", title.display());
            return;
        }

        let htk = [0x5Au8; 16]; // arbitrary key: encoder and reader share it
        let out = tempfile::tempdir().unwrap();

        let mut source = SourceDisc::open(&title).unwrap();
        let plan = plan_disc(&mut source, &VideoPatches::default(), true, false).unwrap();
        let stats = build_nfs(&mut source, &htk, out.path(), &plan).unwrap();
        std::fs::write(out.path().join("htk.bin"), htk).unwrap();

        // Sparse storage must be materially smaller than the 4.2 GB logical partition.
        assert!(
            stats.total_bytes < 3_000_000_000,
            "sparse NFS should skip the gaps; got {} bytes",
            stats.total_bytes
        );

        // name -> (logical offset, length) for every file in the source FST.
        let src = SourceDisc::open(&title).unwrap();
        let files: HashMap<String, (u64, u64)> = {
            let mut part = src.open_data_partition().unwrap();
            let meta = part.meta().unwrap();
            let fst = meta.fst().unwrap();
            fst.iter()
                .filter(|(_, n, _)| !n.is_dir())
                .map(|(_, n, name)| {
                    (
                        name.unwrap_or_default().into_owned(),
                        (n.offset(true), n.length()),
                    )
                })
                .collect()
        };
        assert!(!files.is_empty());

        // Reopen the NFS with hash validation on; reading each file fails on any bad H0/H1/H2/H3.
        let nfs = nod::Disc::new_with_options(
            out.path().join("hif_000000.nfs"),
            &nod::OpenOptions {
                rebuild_encryption: false,
                validate_hashes: true,
            },
        )
        .unwrap();
        let mut nfs_part = nfs.open_partition_kind(nod::PartitionKind::Data).unwrap();
        let mut src_part = src.open_data_partition().unwrap();

        let mut checked = 0;
        for (name, (off, len)) in &files {
            if *len == 0 {
                continue;
            }
            let mut a = vec![0u8; *len as usize];
            let mut b = vec![0u8; *len as usize];
            nfs_part.seek(SeekFrom::Start(*off)).unwrap();
            nfs_part
                .read_exact(&mut a)
                .unwrap_or_else(|e| panic!("hash-validation error reading {name}: {e}"));
            src_part.seek(SeekFrom::Start(*off)).unwrap();
            src_part.read_exact(&mut b).unwrap();
            assert_eq!(a, b, "file {name} differs through the sparse rebuild");
            checked += 1;
        }
        assert!(checked > 0, "expected to check at least one file");
    }

    /// End-to-end check of zero-fill trimming on Brawl (two ~191 MiB all-zero `dummy*.dat` files):
    ///
    /// * building with `trim_zeros` materially shrinks the NFS and stays within the EGGS range cap;
    /// * every **real** (non-dummy) file still reads back byte-for-byte through `nod`'s hash
    ///   validation — trimming must not corrupt or drop any real data;
    /// * a trimmed dummy region reconstructs as zeros with validation **off**.
    ///
    /// Note the dummy region is *not* hash-valid if read with validation on — like the skipped
    /// inter-file gaps, a trimmed group has no stored hash blocks, so `nod` (with
    /// `rebuild_encryption: false`, as the console reads) reports `Invalid H0 hash`. Trimming is safe
    /// only because dummy/padding files are never read. Ignored (reads a multi-GB disc).
    #[test]
    #[ignore = "reads the Brawl disc; checks zero-fill trimming shrinks the NFS without corrupting real files"]
    fn zero_trim_shrinks_nfs() {
        use crate::disc_patch::plan_disc;
        use crate::video::VideoPatches;
        use std::io::{Read, Seek, SeekFrom};

        let title = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../test_titles/Super Smash Bros. Brawl (USA) (Rev 2).rvz");
        if !title.exists() {
            eprintln!("skipping: {} not present", title.display());
            return;
        }
        let htk = [0x5Au8; 16];

        let build = |trim: bool| {
            let out = tempfile::tempdir().unwrap();
            let mut source = SourceDisc::open(&title).unwrap();
            let plan = plan_disc(&mut source, &VideoPatches::default(), true, trim).unwrap();
            let stats = build_nfs(&mut source, &htk, out.path(), &plan).unwrap();
            (out, stats)
        };
        let (_off_dir, off) = build(false);
        let (on_dir, on) = build(true);
        eprintln!(
            "NFS bytes: trim-off={} trim-on={} saved={} MiB; ranges off={} on={}",
            off.total_bytes,
            on.total_bytes,
            (off.total_bytes - on.total_bytes) / (1024 * 1024),
            off.ranges.len(),
            on.ranges.len()
        );

        // The dummy files are ~381 MiB; trimming must reclaim most of that.
        assert!(
            off.total_bytes > on.total_bytes + 300_000_000,
            "trim should save ~381 MiB: off={} on={}",
            off.total_bytes,
            on.total_bytes
        );
        // The range table must stay within the EGGS cap even after the extra splits.
        assert!(
            on.ranges.len() <= 61,
            "too many ranges: {}",
            on.ranges.len()
        );

        // Classify FST files into the trimmed dummies and the five largest real files.
        let src = SourceDisc::open(&title).unwrap();
        let mut dummies: Vec<(u64, u64)> = Vec::new();
        let mut real: Vec<(String, u64, u64)> = Vec::new();
        {
            let mut part = src.open_data_partition().unwrap();
            let meta = part.meta().unwrap();
            let fst = meta.fst().unwrap();
            for (_, n, name) in fst.iter() {
                if n.is_dir() || n.length() == 0 {
                    continue;
                }
                let nm = name.map(|c| c.into_owned()).unwrap_or_default();
                if nm.starts_with("dummy") {
                    dummies.push((n.offset(true), n.length()));
                } else {
                    real.push((nm, n.offset(true), n.length()));
                }
            }
        }
        assert!(!dummies.is_empty(), "expected dummy files in Brawl");
        real.sort_by_key(|(_, _, l)| std::cmp::Reverse(*l));
        real.truncate(5);

        std::fs::write(on_dir.path().join("htk.bin"), htk).unwrap();
        let open = |validate: bool| {
            nod::Disc::new_with_options(
                on_dir.path().join("hif_000000.nfs"),
                &nod::OpenOptions {
                    rebuild_encryption: false,
                    validate_hashes: validate,
                },
            )
            .unwrap()
            .open_partition_kind(nod::PartitionKind::Data)
            .unwrap()
        };

        // Regression guard: with validation ON, the largest real files must read back byte-for-byte
        // (trimming must not disturb any stored group).
        let mut nfs_part = open(true);
        let mut src_part = src.open_data_partition().unwrap();
        for (name, off_, len) in &real {
            let n = (*len).min(8 * 1024 * 1024) as usize;
            let (mut a, mut b) = (vec![0u8; n], vec![0u8; n]);
            nfs_part.seek(SeekFrom::Start(*off_)).unwrap();
            nfs_part
                .read_exact(&mut a)
                .unwrap_or_else(|e| panic!("validation error reading real file {name}: {e}"));
            src_part.seek(SeekFrom::Start(*off_)).unwrap();
            src_part.read_exact(&mut b).unwrap();
            assert_eq!(a, b, "real file {name} changed through trimming");
        }

        // The trimmed dummy region reconstructs as zeros (validation OFF; it is not hash-valid if
        // read — see the note above).
        let mut p0 = open(false);
        let (doff, dlen) = dummies[0];
        let n = dlen.min(8 * 1024 * 1024) as usize;
        let mut buf = vec![0xFFu8; n];
        p0.seek(SeekFrom::Start(doff + dlen / 2 - n as u64 / 2))
            .unwrap();
        p0.read_exact(&mut buf).unwrap();
        assert!(
            buf.iter().all(|&b| b == 0),
            "trimmed dummy must read back as zeros"
        );
    }
}
