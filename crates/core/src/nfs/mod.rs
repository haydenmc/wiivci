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

use crate::error::{Error, Result};
use crate::input::{SourceDisc, DISC_SECTOR_SIZE};
use eggs::{EggsHeader, LbaRange};
use split::SplitWriter;

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
/// `out_dir` must already exist. Returns statistics about the files written.
pub fn build_nfs(source: &mut SourceDisc, htk: &[u8; 16], out_dir: &Path) -> Result<NfsStats> {
    let ranges = structural_ranges(source);
    let header = EggsHeader::new(ranges.clone())?;

    let mut writer = SplitWriter::new(out_dir)?;
    writer.write_all(&header.to_bytes())?;

    let disc_size = source.disc_size();
    let mut sector = vec![0u8; DISC_SECTOR_SIZE];
    let disc = source.stream();

    for range in &ranges {
        for s in range.start_sector..range.start_sector + range.num_sectors {
            let offset = s as u64 * DISC_SECTOR_SIZE as u64;
            read_sector(disc, offset, disc_size, &mut sector)?;
            crypto::encrypt_sector(htk, s, &mut sector);
            writer.write_all(&sector)?;
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

    /// End-to-end round-trip oracle: encode a real Wii disc to NFS, then read it back with
    /// `nod` and confirm every stored sector matches the source disc byte-for-byte.
    ///
    /// Uses `test_titles/Wii Sports (USA).rvz` if present; skipped otherwise. Ignored by
    /// default because it reads several GB — run with `cargo test --release -- --ignored`.
    #[test]
    #[ignore = "reads multi-GB disc; run manually with the test title present"]
    fn nfs_round_trips_through_nod() {
        use sha1::{Digest, Sha1};

        let title = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../test_titles/Wii Sports (USA).rvz");
        if !title.exists() {
            eprintln!("skipping: {} not present", title.display());
            return;
        }

        let htk = [0x5Au8; 16]; // arbitrary key: encoder and reader share it, so any key round-trips
        let out = tempfile::tempdir().unwrap();

        // Encode.
        let mut source = SourceDisc::open(&title).unwrap();
        let ranges = structural_ranges(&source);
        let stats = build_nfs(&mut source, &htk, out.path()).unwrap();
        assert_eq!(stats.ranges, ranges);

        // nod's NFS reader looks for the key at ../code/htk.bin or ./htk.bin.
        std::fs::write(out.path().join("htk.bin"), htk).unwrap();

        // Hash the covered sectors from the source disc.
        let mut source = SourceDisc::open(&title).unwrap();
        let disc_size = source.disc_size();
        let src_hash = hash_ranges(source.stream(), disc_size, &ranges);

        // Hash the same logical sectors read back from the NFS via nod.
        let nfs = nod::Disc::new_with_options(
            out.path().join("hif_000000.nfs"),
            &nod::OpenOptions {
                rebuild_encryption: false,
                ..Default::default()
            },
        )
        .unwrap();
        let nfs_size = nfs.disc_size();
        let mut nfs_stream = nfs;
        let nfs_hash = hash_ranges(&mut nfs_stream, nfs_size, &ranges);

        assert_eq!(
            src_hash, nfs_hash,
            "NFS round-trip through nod must be lossless"
        );

        fn hash_ranges<R: Read + Seek>(disc: &mut R, size: u64, ranges: &[LbaRange]) -> [u8; 20] {
            let mut hasher = Sha1::new();
            let mut buf = vec![0u8; DISC_SECTOR_SIZE];
            for range in ranges {
                for s in range.start_sector..range.start_sector + range.num_sectors {
                    let offset = s as u64 * DISC_SECTOR_SIZE as u64;
                    read_sector(disc, offset, size, &mut buf).unwrap();
                    hasher.update(&buf);
                }
            }
            hasher.finalize().into()
        }
    }
}
