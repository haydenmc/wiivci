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
use crate::input::{SourceDisc, DISC_SECTOR_SIZE};
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

/// Compute the sparse LBA ranges covering the disc's meaningful sectors.
///
/// * `{0, 1}`  — the disc header (game id, magic).
/// * `{8, 2}`  — the partition table (0x40000) and region info (0x4E000).
/// * one range per partition: `{start_sector, data_end_sector - start_sector}` — each
///   partition's ticket/TMD/cert/H3 header followed by its decrypted cluster data.
///
/// Everything else (large inter-partition gaps) is an implicit run of zeros. All partitions
/// are preserved so the stored logical disc is bit-identical to the retail dump; trimming to
/// the data partition alone is a future size optimization.
fn structural_ranges(source: &SourceDisc) -> Vec<LbaRange> {
    let mut ranges = vec![
        LbaRange {
            start_sector: 0,
            num_sectors: 1,
        },
        LbaRange {
            start_sector: 8,
            num_sectors: 2,
        },
    ];
    for span in source.partitions() {
        ranges.push(LbaRange {
            start_sector: span.start_sector,
            num_sectors: span.data_end_sector - span.start_sector,
        });
    }
    ranges
}

/// Build the NFS files for `source` into `out_dir` using the 16-byte `htk` key.
///
/// `out_dir` must already exist. `plan` (from [`crate::disc_patch::plan_disc`]) drives the
/// per-partition Wii hash-tree rebuild — RVZ/WIA sources zero the per-cluster hash blocks, so
/// they are recomputed here — and any `main.dol` video patches. Returns statistics about the
/// files written.
pub fn build_nfs(
    source: &mut SourceDisc,
    htk: &[u8; 16],
    out_dir: &Path,
    plan: &DiscPlan,
) -> Result<NfsStats> {
    let ranges = structural_ranges(source);
    let header = EggsHeader::new(ranges.clone())?;

    let mut writer = SplitWriter::new(out_dir)?;
    writer.write_all(&header.to_bytes())?;

    let disc_size = source.disc_size();
    let mut sector = vec![0u8; DISC_SECTOR_SIZE];
    let disc = source.stream();

    for range in &ranges {
        match plan
            .partitions
            .iter()
            .find(|p| p.start_sector == range.start_sector)
        {
            Some(pp) => write_partition(&mut writer, disc, htk, pp, disc_size)?,
            None => {
                // Disc header / partition table: copied verbatim.
                for s in range.start_sector..range.start_sector + range.num_sectors {
                    read_sector(
                        disc,
                        s as u64 * DISC_SECTOR_SIZE as u64,
                        disc_size,
                        &mut sector,
                    )?;
                    crypto::encrypt_sector(htk, s, &mut sector);
                    writer.write_all(&sector)?;
                }
            }
        }
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
/// then its cluster data with the Wii hash tree rebuilt group-by-group and `main.dol` edits
/// applied.
fn write_partition<R: Read + Seek>(
    writer: &mut SplitWriter,
    disc: &mut R,
    htk: &[u8; 16],
    pp: &PartitionPlan,
    disc_size: u64,
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

    // Cluster region: rebuild the hash tree one 64-cluster group at a time.
    let total = (pp.data_end_sector - pp.data_start_sector) as u64;
    let ngroups = total.div_ceil(SECTORS_PER_GROUP as u64);
    let mut clusters = vec![[0u8; DISC_SECTOR_SIZE]; SECTORS_PER_GROUP];
    for g in 0..ngroups {
        for (k, cluster) in clusters.iter_mut().enumerate() {
            let ps = g * SECTORS_PER_GROUP as u64 + k as u64;
            if ps < total {
                let off = (pp.data_start_sector as u64 + ps) * DISC_SECTOR_SIZE as u64;
                read_sector(disc, off, disc_size, cluster)?;
            } else {
                cluster.fill(0);
            }
        }
        apply_edits_to_group(&mut clusters, g as u32, &pp.edits);
        recompute_group(&mut clusters);
        for (k, cluster) in clusters.iter_mut().enumerate() {
            let ps = g * SECTORS_PER_GROUP as u64 + k as u64;
            if ps < total {
                let s = pp.data_start_sector + ps as u32;
                crypto::encrypt_sector(htk, s, cluster);
                writer.write_all(cluster)?;
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
fn read_sector<R: Read + Seek>(
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

    /// End-to-end oracle: encode a real Wii disc to NFS (rebuilding the Wii hash tree), then
    /// reopen it with `nod`'s hash **validation** enabled and confirm the whole data partition
    /// reads without a hash error and its logical bytes match the source. This proves the
    /// rebuilt H0/H1/H2 blocks and H3 tables are internally consistent (the property a real VC
    /// checks) — which a plain byte round-trip could not, since RVZ zeroes the source hashes.
    ///
    /// Uses `test_titles/Wii Sports (USA).rvz` if present; skipped otherwise. Ignored by
    /// default because it reads several GB — run with `cargo test --release -- --ignored`.
    #[test]
    #[ignore = "reads multi-GB disc; run manually with the test title present"]
    fn nfs_rebuilds_valid_wii_hashes() {
        use crate::disc_patch::plan_disc;
        use crate::video::VideoPatches;

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
        build_nfs(&mut source, &htk, out.path(), &plan).unwrap();
        std::fs::write(out.path().join("htk.bin"), htk).unwrap();

        // Read the source's logical data-partition bytes.
        let src = SourceDisc::open(&title).unwrap();
        let mut src_part = src.open_data_partition().unwrap();
        let mut src_data = Vec::new();
        src_part.read_to_end(&mut src_data).unwrap();

        // Reopen the NFS with hash validation on; any invalid H0/H1/H2/H3 fails the read.
        let nfs = nod::Disc::new_with_options(
            out.path().join("hif_000000.nfs"),
            &nod::OpenOptions {
                rebuild_encryption: false,
                validate_hashes: true,
            },
        )
        .unwrap();
        let mut nfs_part = nfs.open_partition_kind(nod::PartitionKind::Data).unwrap();
        let mut nfs_data = Vec::new();
        nfs_part
            .read_to_end(&mut nfs_data)
            .expect("reading the rebuilt NFS must not raise a hash-validation error");

        assert_eq!(
            src_data, nfs_data,
            "logical data must be preserved through the rebuild"
        );
    }
}
