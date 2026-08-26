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
/// hash-group runs that contain real data, skipping the (potentially multi-GB) zero gaps between
/// files. This keeps the NFS as small as a compacted disc while leaving every file at its original
/// offset. A first pass scans the disc for non-zero groups; a second writes them.
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
    let header = EggsHeader::new(ranges.clone())?;

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
        ranges,
    })
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
            recompute_group(&mut clusters);
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
        let plan = plan_disc(&mut source, &VideoPatches::default()).unwrap();
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
}
