//! Patching the Wii game's `main.dol` inside the disc, and rebuilding the Wii partition hash
//! tree over the affected clusters.
//!
//! The pipeline packs the *decrypted* disc straight into NFS (see [`crate::nfs`]), so a
//! `main.dol` edit ([`crate::video`]) has to be applied to the partition's physical clusters and
//! the Wii hash tree recomputed — otherwise the emulated Wii's integrity check rejects the disc.
//!
//! Wii partition layout (all confirmed against `nod`'s reader, the authoritative round-trip
//! oracle): each 0x8000 cluster is a 0x400 hash block followed by 0x7C00 of data (31 × 0x400
//! sub-blocks). The hash block holds `H0` (31 hashes of the sub-blocks, `0x000..0x26C`), the
//! subgroup's `H1` table (8 hashes, `0x280..0x320`) and the group's `H2` table (8 hashes,
//! `0x340..0x3E0`). `H1[s] = SHA1(sector s's H0 region)`, `H2[g] = SHA1(subgroup g's H1
//! region)`, `H3[group] = SHA1(group's H2 region)`. The `H3` values live in the partition's H3
//! table, and the partition TMD's single content hash is `SHA1(H3 table)`.
//!
//! We recompute only the groups a patch touches; every other cluster streams through unchanged,
//! so an un-patched build stays byte-identical to before.

use std::collections::BTreeSet;
use std::io::{Read, Seek, SeekFrom};

use sha1::{Digest, Sha1};

use crate::error::{Error, Result};
use crate::input::SourceDisc;
use crate::video::{find_dol_edits, VideoPatches};

const SECTOR: usize = 0x8000;
const HASH_BLOCK: usize = 0x400;
const DATA: usize = SECTOR - HASH_BLOCK; // 0x7C00
const SUBBLOCK: usize = 0x400;
const N_SUBBLOCKS: usize = 31;
const SECTORS_PER_SUBGROUP: usize = 8;
const SECTORS_PER_GROUP: usize = 64;

// Sub-regions within a cluster's 0x400 hash block.
const H0_REGION: usize = N_SUBBLOCKS * 20; // 0x26C
const H1_OFF: usize = 0x280;
const H1_REGION: usize = SECTORS_PER_SUBGROUP * 20; // 0xA0
const H2_OFF: usize = 0x340;
const H2_REGION: usize = 8 * 20; // 0xA0

/// Offset of the `h3_table_off` u32 (stored `>> 2`) within the partition header.
const H3_TABLE_OFF_FIELD: u64 = 0x2B4;

fn be32(b: &[u8]) -> u32 {
    u32::from_be_bytes([b[0], b[1], b[2], b[3]])
}

fn sha1(buf: &[u8]) -> [u8; 20] {
    Sha1::digest(buf).into()
}

/// The result of patching the disc: full replacement clusters/sectors (keyed by disc sector,
/// Per-partition plan consumed by [`crate::nfs::build_nfs`].
#[derive(Clone)]
pub struct PartitionPlan {
    /// First sector of the partition on the logical disc.
    pub start_sector: u32,
    /// First cluster sector of the (decrypted) partition data.
    pub data_start_sector: u32,
    /// One past the last cluster sector.
    pub data_end_sector: u32,
    /// Byte-range overlays applied to the partition's pre-data header region (the rebuilt H3
    /// table, and — when patched — the embedded TMD's content hash and fakesigned signature).
    /// Keyed by absolute disc byte offset.
    pub header_patches: Vec<(u64, Vec<u8>)>,
    /// `main.dol` edits, as (logical partition-data offset, replacement bytes). Data partition
    /// only; empty otherwise.
    pub edits: Vec<(u64, Vec<u8>)>,
    /// Runs of 64-cluster hash groups (0-based within the data region) that hold real data and
    /// must be stored; the rest are inter-file gaps skipped in the NFS (sparse storage, no
    /// compaction). Empty means "store every group" (used by the synthetic GC disc).
    pub stored_data_groups: Vec<(u32, u32)>,
}

/// A whole-disc rebuild plan: how to rebuild each partition's Wii hash tree (and apply any
/// `main.dol` edits) while streaming the NFS.
#[derive(Clone)]
pub struct DiscPlan {
    /// One entry per stored partition, matched to a structural range by `start_sector`.
    pub partitions: Vec<PartitionPlan>,
    /// Byte-range overlays applied to the disc-level (non-partition) sectors — used to rewrite the
    /// partition table so it lists only the data partition. Keyed by absolute disc byte offset.
    pub disc_patches: Vec<(u64, Vec<u8>)>,
    /// New content hash for the emitted `rvlt.tmd`, set only when the data partition was patched.
    pub rvlt_content_hash: Option<[u8; 20]>,
    /// Names of the video patches that matched and were applied.
    pub applied: Vec<&'static str>,
}

/// Recompute the H0/H1/H2 hash blocks of a full 64-cluster group in place and return its H3.
///
/// `clusters` must be exactly [`SECTORS_PER_GROUP`] clusters of [`SECTOR`] bytes; clusters that
/// fall past the partition end should be passed zero-filled (matching `nod`'s zero-sector
/// padding).
pub fn recompute_group(clusters: &mut [[u8; SECTOR]]) -> [u8; 20] {
    assert_eq!(clusters.len(), SECTORS_PER_GROUP);

    // H0: hash each 0x400 data sub-block into the cluster's H0 region.
    for cluster in clusters.iter_mut() {
        for i in 0..N_SUBBLOCKS {
            let data = &cluster[(i + 1) * SUBBLOCK..(i + 2) * SUBBLOCK];
            let h = sha1(data);
            cluster[i * 20..i * 20 + 20].copy_from_slice(&h);
        }
    }

    // H1: per subgroup (8 sectors), hash each sector's H0 region; the 8-entry table is stored
    // in every sector of the subgroup.
    for sg in 0..SECTORS_PER_GROUP / SECTORS_PER_SUBGROUP {
        let mut table = [0u8; H1_REGION];
        for s in 0..SECTORS_PER_SUBGROUP {
            let h = sha1(&clusters[sg * SECTORS_PER_SUBGROUP + s][..H0_REGION]);
            table[s * 20..s * 20 + 20].copy_from_slice(&h);
        }
        for s in 0..SECTORS_PER_SUBGROUP {
            clusters[sg * SECTORS_PER_SUBGROUP + s][H1_OFF..H1_OFF + H1_REGION]
                .copy_from_slice(&table);
        }
    }

    // H2: hash each subgroup's H1 region; the 8-entry table is stored in every sector of the
    // group.
    let mut h2_table = [0u8; H2_REGION];
    for sg in 0..SECTORS_PER_GROUP / SECTORS_PER_SUBGROUP {
        let h = sha1(&clusters[sg * SECTORS_PER_SUBGROUP][H1_OFF..H1_OFF + H1_REGION]);
        h2_table[sg * 20..sg * 20 + 20].copy_from_slice(&h);
    }
    for cluster in clusters.iter_mut() {
        cluster[H2_OFF..H2_OFF + H2_REGION].copy_from_slice(&h2_table);
    }

    // H3: hash the group's H2 region.
    sha1(&clusters[0][H2_OFF..H2_OFF + H2_REGION])
}

fn read_at<R: Read + Seek>(disc: &mut R, offset: u64, out: &mut [u8]) -> Result<()> {
    disc.seek(SeekFrom::Start(offset))
        .map_err(|e| Error::io("<disc>", e))?;
    disc.read_exact(out).map_err(|e| Error::io("<disc>", e))?;
    Ok(())
}

// Offsets within the partition header (at `start_sector * SECTOR`).
const TMD_OFF_FIELD: u64 = 0x2A8; // u32, stored >> 2
const SIG: std::ops::Range<usize> = 0x004..0x104; // RSA-2048 signature (zeroed to fakesign)
const TMD_CONTENT0_HASH: usize = 0x1F4; // Wii TMD single content hash

// The partition's own ticket sits at the partition start (offset 0); its signature shares the
// same 0x004..0x104 layout as the TMD's.
const TICKET_SIG: std::ops::Range<usize> = SIG;
const TMD_SIG: std::ops::Range<usize> = SIG;

// Disc-level region info: the per-organisation age ratings (zeroed by the reference injectors).
const REGION_AGE_RATINGS_OFF: u64 = 0x4E010;
const REGION_AGE_RATINGS_LEN: usize = 0x10;

/// Byte offsets of the disc partition table (a Wii inject keeps only the DATA partition).
const PARTITION_GROUPS_OFF: u64 = 0x40000; // four 8-byte group entries
const PARTITION_INFO_OFF: u64 = 0x40020; // partition info entries (8 bytes each)

/// Rewrite the partition table to list a single DATA partition at `data_part_off` (byte offset).
/// A retail Wii disc has an UPDATE partition (a system-update IOS) before the game partition; a
/// VC inject must present only the data partition, or the Wii U's emulator hangs at boot.
fn partition_table_patches(data_part_off: u64) -> Vec<(u64, Vec<u8>)> {
    // Group table: group 0 has one partition, its info table at PARTITION_INFO_OFF; groups 1..3
    // are empty. (0x20 bytes total, overwriting any UPDATE-partition group entry.)
    let mut groups = vec![0u8; 0x20];
    groups[0..4].copy_from_slice(&1u32.to_be_bytes());
    groups[4..8].copy_from_slice(&((PARTITION_INFO_OFF >> 2) as u32).to_be_bytes());
    // Info table: entry 0 = { partition_offset >> 2, type = 0 (DATA) }; the remaining three entry
    // slots are cleared so a stale second entry from the source disc can't linger (the reference
    // injectors leave only one entry). 0x20 bytes = four 8-byte entries.
    let mut info = vec![0u8; 0x20];
    info[0..4].copy_from_slice(&((data_part_off >> 2) as u32).to_be_bytes());
    vec![
        (PARTITION_GROUPS_OFF, groups),
        (PARTITION_INFO_OFF, info),
        (REGION_AGE_RATINGS_OFF, vec![0u8; REGION_AGE_RATINGS_LEN]),
    ]
}

/// Plan the disc rebuild (and any `main.dol` video patches).
///
/// Only the **data (game) partition** is stored — the retail UPDATE partition is dropped and the
/// partition table rewritten to list just the data partition, matching how the reference injectors
/// build a bootable VC disc. `build_nfs` streams the data partition once and rebuilds its per-cluster
/// hash blocks (RVZ/WIA sources zero them); the H3 table is valid via `nod`. Any `main.dol` edits
/// recompute the affected groups' H3 and re-fakesign the embedded TMD.
pub fn plan_disc(source: &mut SourceDisc, patches: &VideoPatches) -> Result<DiscPlan> {
    let span = source.data_partition();

    // Data-partition main.dol edits (logical offsets), if any pattern matched.
    let mut edits: Vec<(u64, Vec<u8>)> = Vec::new();
    let mut applied: Vec<&'static str> = Vec::new();
    if patches.any() {
        let dol = source.read_main_dol()?;
        for e in find_dol_edits(&dol.data, patches) {
            if !applied.contains(&e.label) {
                applied.push(e.label);
            }
            edits.push((dol.offset + e.offset as u64, e.bytes));
        }
    }

    let part_base = span.start_sector as u64 * SECTOR as u64;
    let mut off_field = [0u8; 4];
    read_at(
        source.stream(),
        part_base + H3_TABLE_OFF_FIELD,
        &mut off_field,
    )?;
    let h3_base = part_base + ((be32(&off_field) as u64) << 2);

    // The H3 table is valid on disc even for RVZ; use it as the base.
    let mut h3_table = source.partition_h3_table(span.index)?;
    let mut header_patches: Vec<(u64, Vec<u8>)> = Vec::new();

    if !edits.is_empty() {
        // Recompute the H3 of each group an edit touches so the H3 table stays consistent.
        let total = (span.data_end_sector - span.data_start_sector) as u64;
        let mut groups: BTreeSet<u32> = BTreeSet::new();
        for (off, bytes) in &edits {
            let first = off / DATA as u64;
            let last = (off + bytes.len() as u64 - 1) / DATA as u64;
            for ps in first..=last {
                groups.insert((ps / SECTORS_PER_GROUP as u64) as u32);
            }
        }
        for &g in &groups {
            let mut clusters = vec![[0u8; SECTOR]; SECTORS_PER_GROUP];
            for (k, cluster) in clusters.iter_mut().enumerate() {
                let ps = g as u64 * SECTORS_PER_GROUP as u64 + k as u64;
                if ps < total {
                    read_at(
                        source.stream(),
                        (span.data_start_sector as u64 + ps) * SECTOR as u64,
                        cluster,
                    )?;
                }
            }
            apply_edits_to_group(&mut clusters, g, &edits);
            let h3 = recompute_group(&mut clusters);
            h3_table[g as usize * 20..g as usize * 20 + 20].copy_from_slice(&h3);
        }
    }

    // The partition's content hash is SHA1 of the (possibly rebuilt) H3 table. This is unchanged
    // from the source when there were no edits.
    let content_hash = sha1(&h3_table);
    let rvlt_content_hash = Some(content_hash);

    // Fakesign the partition's OWN in-disc ticket and TMD (zero the RSA signatures) and set the
    // TMD's content hash. The Wii U's patched fw.img accepts a zeroed signature and *rejects* a
    // real one, so the partition must be fakesigned in place — not just the external rvlt.tik/tmd
    // — or the emulator hangs at boot even though the disc is otherwise valid. (Confirmed by
    // diffing a known-good TeconMoon inject: both in-disc signatures are zeroed.)
    let mut tmd_off = [0u8; 4];
    read_at(source.stream(), part_base + TMD_OFF_FIELD, &mut tmd_off)?;
    let tmd_base = part_base + ((be32(&tmd_off) as u64) << 2);
    header_patches.push((
        part_base + TICKET_SIG.start as u64,
        vec![0u8; TICKET_SIG.len()],
    ));
    header_patches.push((tmd_base + TMD_SIG.start as u64, vec![0u8; TMD_SIG.len()]));
    header_patches.push((tmd_base + TMD_CONTENT0_HASH as u64, content_hash.to_vec()));

    // Always (re)write the valid H3 table so we don't depend on the stream's copy.
    header_patches.push((h3_base, h3_table));

    // Sparse storage: only the hash groups the FST (and boot structures) actually use are written
    // to the NFS; the multi-GB inter-file gaps are skipped without relocating any file.
    let stored_data_groups = source.used_data_group_runs()?;

    let partitions = vec![PartitionPlan {
        start_sector: span.start_sector,
        data_start_sector: span.data_start_sector,
        data_end_sector: span.data_end_sector,
        header_patches,
        edits,
        stored_data_groups,
    }];
    let disc_patches = partition_table_patches(part_base);

    if !applied.is_empty() {
        log::info!("applying main.dol patches: {}", applied.join(", "));
    }
    Ok(DiscPlan {
        partitions,
        disc_patches,
        rvlt_content_hash,
        applied,
    })
}

/// Apply the edits that fall within group `g` to its 64 cluster buffers.
pub(crate) fn apply_edits_to_group(
    clusters: &mut [[u8; SECTOR]],
    g: u32,
    edits: &[(u64, Vec<u8>)],
) {
    for (off, bytes) in edits {
        for (bi, &b) in bytes.iter().enumerate() {
            let l = off + bi as u64;
            let ps = l / DATA as u64;
            if (ps / SECTORS_PER_GROUP as u64) as u32 != g {
                continue;
            }
            let k = (ps % SECTORS_PER_GROUP as u64) as usize;
            let within = (l % DATA as u64) as usize;
            clusters[k][HASH_BLOCK + within] = b;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Independent re-implementation of `nod`'s per-sector hash verification, used to prove our
    /// recompute produces a self-consistent tree.
    fn verify_group(clusters: &[[u8; SECTOR]], h3_table_entry: &[u8; 20]) {
        for (part_sector, cluster) in clusters.iter().enumerate() {
            let sector = part_sector % SECTORS_PER_SUBGROUP;
            let sub_group = (part_sector / SECTORS_PER_SUBGROUP) % SECTORS_PER_SUBGROUP;

            for i in 0..N_SUBBLOCKS {
                let expected = &cluster[i * 20..i * 20 + 20];
                let got = sha1(&cluster[(i + 1) * SUBBLOCK..(i + 2) * SUBBLOCK]);
                assert_eq!(expected, got, "H0 mismatch sector {part_sector} block {i}");
            }
            let h1 = sha1(&cluster[..H0_REGION]);
            assert_eq!(
                &cluster[H1_OFF + sector * 20..H1_OFF + sector * 20 + 20],
                h1
            );
            let h2 = sha1(&cluster[H1_OFF..H1_OFF + H1_REGION]);
            assert_eq!(
                &cluster[H2_OFF + sub_group * 20..H2_OFF + sub_group * 20 + 20],
                h2
            );
        }
        let h3 = sha1(&clusters[0][H2_OFF..H2_OFF + H2_REGION]);
        assert_eq!(&h3, h3_table_entry, "H3 mismatch");
    }

    fn sample_group() -> Vec<[u8; SECTOR]> {
        let mut clusters = vec![[0u8; SECTOR]; SECTORS_PER_GROUP];
        // Deterministic pseudo-data in the data region of each cluster.
        for (c, cluster) in clusters.iter_mut().enumerate() {
            for (idx, byte) in cluster[HASH_BLOCK..].iter_mut().enumerate() {
                let j = HASH_BLOCK + idx;
                *byte = ((c * 7 + j * 3) & 0xFF) as u8;
            }
        }
        clusters
    }

    #[test]
    fn recompute_produces_self_consistent_tree() {
        let mut clusters = sample_group();
        let h3 = recompute_group(&mut clusters);
        verify_group(&clusters, &h3);
    }

    #[test]
    fn h1_and_h2_tables_are_replicated_across_the_subgroup_and_group() {
        let mut clusters = sample_group();
        recompute_group(&mut clusters);
        // H1 table identical within each subgroup.
        for sg in 0..8 {
            let first = clusters[sg * 8][H1_OFF..H1_OFF + H1_REGION].to_vec();
            for s in 1..8 {
                assert_eq!(
                    &clusters[sg * 8 + s][H1_OFF..H1_OFF + H1_REGION],
                    first.as_slice()
                );
            }
        }
        // H2 table identical across the whole group.
        let h2 = clusters[0][H2_OFF..H2_OFF + H2_REGION].to_vec();
        for cluster in clusters.iter().skip(1) {
            assert_eq!(&cluster[H2_OFF..H2_OFF + H2_REGION], h2.as_slice());
        }
    }

    #[test]
    fn a_single_data_byte_change_propagates_to_h3() {
        let mut a = sample_group();
        let h3a = recompute_group(&mut a);
        let mut b = sample_group();
        b[20][HASH_BLOCK + 1234] ^= 0xFF; // flip a byte in cluster 20's data
        let h3b = recompute_group(&mut b);
        assert_ne!(h3a, h3b, "changing data must change the group's H3");
        verify_group(&b, &h3b);
    }

    /// Full end-to-end: patch Wii Sports' main.dol (all three patches), build the NFS, reopen it
    /// with `nod`'s hash validation, and confirm main.dol reads back patched with no hash error
    /// and the emitted TMD content hash matches the rebuilt H3 table. Needs the test title.
    #[test]
    #[ignore = "reads the Wii Sports disc; validates a patched NFS via nod hash verification"]
    fn patched_dol_verifies_through_nod() {
        use crate::nfs::build_nfs;
        use crate::video::find_dol_edits;
        use std::io::{Read, Seek, SeekFrom};

        let title = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../test_titles/Wii Sports (USA).rvz");
        if !title.exists() {
            eprintln!("skipping: {} not present", title.display());
            return;
        }
        let patches = VideoPatches {
            deflicker: true,
            half_vfilter: true,
            dithering: true,
        };

        // Capture the original main.dol and the edits we expect.
        let src0 = SourceDisc::open(&title).unwrap();
        let dol = src0.read_main_dol().unwrap();
        let edits = find_dol_edits(&dol.data, &patches);
        assert!(
            !edits.is_empty(),
            "expected at least one pattern to match Wii Sports' main.dol"
        );
        drop(src0);

        let mut source = SourceDisc::open(&title).unwrap();
        let plan = plan_disc(&mut source, &patches).unwrap();
        let content_hash = plan
            .rvlt_content_hash
            .expect("data partition should be patched");

        let htk = [0x5Au8; 16];
        let out = tempfile::tempdir().unwrap();
        build_nfs(&mut source, &htk, out.path(), &plan).unwrap();
        std::fs::write(out.path().join("htk.bin"), htk).unwrap();

        let nfs = nod::Disc::new_with_options(
            out.path().join("hif_000000.nfs"),
            &nod::OpenOptions {
                rebuild_encryption: false,
                validate_hashes: true,
            },
        )
        .unwrap();
        let mut part = nfs.open_partition_kind(nod::PartitionKind::Data).unwrap();

        // Reading main.dol validates the hash tree over its clusters as a side effect.
        part.seek(SeekFrom::Start(dol.offset)).unwrap();
        let mut back = vec![0u8; dol.data.len()];
        part.read_exact(&mut back)
            .expect("patched clusters must pass hash validation");

        let mut expected = dol.data.clone();
        for e in &edits {
            expected[e.offset..e.offset + e.bytes.len()].copy_from_slice(&e.bytes);
        }
        assert_eq!(
            back, expected,
            "main.dol must read back with exactly the expected patches"
        );

        // The emitted rvlt.tmd content hash must equal SHA1 of the rebuilt H3 table.
        let meta = part.meta().unwrap();
        let h3 = meta.raw_h3_table.unwrap();
        assert_eq!(
            sha1(&h3),
            content_hash,
            "rvlt.tmd content hash must match the rebuilt H3 table"
        );
    }
}
