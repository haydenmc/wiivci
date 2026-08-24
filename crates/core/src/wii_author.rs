//! Authoring a synthetic **Wii disc** that boots Nintendont, for GameCube injection.
//!
//! A GameCube game is injected into a Wii U VC title by wrapping it in a Wii VC title (exactly
//! like a Wii inject) whose "Wii game" is a small synthetic Wii disc: its `main.dol` is
//! **Nintendont**, and the GameCube image sits in the disc filesystem as `files/game.iso`.
//! Nintendont boots, reads `game.iso` from the emulated disc (`di:/game.iso`, see
//! [`crate::nincfg`]) and runs it.
//!
//! This module builds that disc directly in its **decrypted** logical form — the representation
//! [`crate::nfs::build_nfs`] consumes — so the whole existing NFS + Wii hash-tree + packaging
//! pipeline is reused unchanged. We author the disc into a scratch file and expose it as a
//! [`DecryptedDisc`].
//!
//! Layout (all offsets confirmed against `nod` and [`crate::disc_patch`]):
//!
//! ```text
//! 0x00000  disc header (game id, Wii magic 0x5D1C9EA3 @0x18, disc title)
//! 0x40000  partition table: one group, one DATA partition
//! 0x4E000  region info
//! 0x50000  partition:
//!            +0x00000  ticket (0x2A4, fakesigned, arbitrary title key)
//!            +0x002C0  TMD    (one content, hash = SHA1(H3 table), fakesigned)
//!            +0x08000  H3 table (0x18000)
//!            +0x20000  data  (0x8000 clusters: 0x400 hash block + 0x7C00 data)
//! ```
//!
//! The partition data, in its logical (hash-stripped) address space, is:
//! `boot.bin | bi2.bin | apploader | main.dol (Nintendont) | FST | game.iso`.

use std::fs::{File, OpenOptions};
use std::io::{Seek, SeekFrom, Write};
use std::path::Path;

use sha1::{Digest, Sha1};

use crate::disc_patch::{recompute_group, DiscPlan, PartitionPlan};
use crate::error::{Error, Result};
use crate::input::{DecryptedDisc, PartitionSpan, ReadSeek, DISC_SECTOR_SIZE};

const SECTOR: u64 = DISC_SECTOR_SIZE as u64; // 0x8000
const HASH_BLOCK: usize = 0x400;
const CLUSTER_DATA: usize = DISC_SECTOR_SIZE - HASH_BLOCK; // 0x7C00
const SECTORS_PER_GROUP: usize = 64;
const H3_TABLE_SIZE: usize = 0x18000;

// Absolute disc offsets.
const PART_ABS: u64 = 0x50000;
const PARTITION_TABLE_ABS: u64 = 0x40000;
const REGION_INFO_ABS: u64 = 0x4E000;

// Partition-relative offsets.
const TICKET_LEN: usize = 0x2A4;
const TMD_PART_OFF: u64 = 0x2C0;
const H3_PART_OFF: u64 = 0x8000;
const DATA_PART_OFF: u64 = 0x20000;
const DATA_ABS: u64 = PART_ABS + DATA_PART_OFF; // 0x70000

const START_SECTOR: u32 = (PART_ABS / SECTOR) as u32; // 10
const DATA_START_SECTOR: u32 = (DATA_ABS / SECTOR) as u32; // 14

// Logical partition-data layout.
const BOOT_BIN_LEN: usize = 0x440;
const BI2_LEN: usize = 0x2000;
const APPLOADER_OFF: usize = 0x2440;
const ALIGN: usize = 0x20;

// boot.bin fields (partition logical offsets).
const BOOT_DOL_OFF_FIELD: usize = 0x420; // >> 2
const BOOT_FST_OFF_FIELD: usize = 0x424; // >> 2
const BOOT_FST_SIZE_FIELD: usize = 0x428; // >> 2
const BOOT_FST_MAX_FIELD: usize = 0x42C; // >> 2

// Wii signature type: RSA-2048 / SHA-1 (distinct from the WUP 0x00010004 in `package/`).
const WII_SIG_RSA2048_SHA1: u32 = 0x0001_0001;
const TMD_LEN: usize = 0x208; // header .. one 0x24 content record
const TMD_CONTENT0_HASH: usize = 0x1F4;

const DISC_MAGIC_WII: u32 = 0x5D1C_9EA3;

fn align_up(x: usize, a: usize) -> usize {
    x.div_ceil(a) * a
}

fn put_u32(buf: &mut [u8], off: usize, v: u32) {
    buf[off..off + 4].copy_from_slice(&v.to_be_bytes());
}

/// A synthetic Wii disc authored on disk, ready to feed to [`crate::nfs::build_nfs`].
pub struct AuthoredDisc {
    file: File,
    disc_size: u64,
    spans: Vec<PartitionSpan>,
    /// Plan for `build_nfs`: the hash tree is rebuilt from the authored clusters; no patches are
    /// needed because the authored partition header already carries the matching H3 table + TMD.
    pub plan: DiscPlan,
    /// The disc's Wii ticket bytes, to be written as `code/rvlt.tik`.
    pub rvlt_ticket: Vec<u8>,
    /// The disc's Wii TMD bytes, to be written as `code/rvlt.tmd`.
    pub rvlt_tmd: Vec<u8>,
}

impl DecryptedDisc for AuthoredDisc {
    fn partition_spans(&self) -> &[PartitionSpan] {
        &self.spans
    }

    fn disc_size(&self) -> u64 {
        self.disc_size
    }

    fn disc_stream(&mut self) -> &mut dyn ReadSeek {
        &mut self.file
    }
}

/// Build the disc filesystem table (FST) for the single `game.iso` file.
///
/// GameCube/Wii disc FST entries are 12 bytes: `[type:u8][name_off:u24][arg0:u32][arg1:u32]`.
/// The root directory (entry 0) stores the total entry count in `arg1`. The `game.iso` file's
/// data offset is stored `>> 2` (Wii shifts disc offsets).
fn build_fst(iso_data_off: u64, iso_size: u64) -> Vec<u8> {
    let mut v = Vec::new();
    // Root directory: type=1, name_off=0, parent=0, arg1 = total entry count (2).
    v.push(1);
    v.extend_from_slice(&[0, 0, 0]);
    v.extend_from_slice(&0u32.to_be_bytes());
    v.extend_from_slice(&2u32.to_be_bytes());
    // game.iso: type=0 (file), name_off=0, data_off>>2, size.
    v.push(0);
    v.extend_from_slice(&[0, 0, 0]);
    v.extend_from_slice(&((iso_data_off >> 2) as u32).to_be_bytes());
    v.extend_from_slice(&(iso_size as u32).to_be_bytes());
    // String table: names in entry order.
    v.extend_from_slice(b"game.iso\0");
    while v.len() % 4 != 0 {
        v.push(0);
    }
    v
}

/// Assemble the fixed "system" portion of the logical partition data
/// (`boot.bin | bi2 | apploader | main.dol | FST`), returning the blob and the logical offset at
/// which `game.iso` begins (immediately after the FST).
fn build_sys_blob(
    game_id: &[u8; 6],
    disc_title: &str,
    apploader: &[u8],
    main_dol: &[u8],
    iso_size: u64,
) -> (Vec<u8>, u64) {
    // boot.bin + bi2.bin (bi2 is all zero for our purposes).
    let mut sys = vec![0u8; APPLOADER_OFF];
    sys[0..6].copy_from_slice(game_id);
    write_title(&mut sys[0x20..0x20 + 0x40], disc_title);

    // apploader, then 0x20-aligned main.dol, then 0x20-aligned FST.
    sys.extend_from_slice(apploader);
    let aligned = align_up(sys.len(), ALIGN);
    pad_to(&mut sys, aligned);
    let dol_off = sys.len();
    sys.extend_from_slice(main_dol);
    let aligned = align_up(sys.len(), ALIGN);
    pad_to(&mut sys, aligned);
    let fst_off = sys.len();

    // The FST size is fixed (2 entries + "game.iso\0"), so game.iso's offset is known before we
    // serialize the FST (which needs that offset).
    let fst_len = align_up(2 * 12 + b"game.iso\0".len(), 4);
    let iso_off = align_up(fst_off + fst_len, ALIGN);
    let fst = build_fst(iso_off as u64, iso_size);
    debug_assert_eq!(fst.len(), fst_len);
    sys.extend_from_slice(&fst);
    pad_to(&mut sys, iso_off);

    // Fill boot.bin's offset table now that the layout is known.
    put_u32(&mut sys, BOOT_DOL_OFF_FIELD, (dol_off >> 2) as u32);
    put_u32(&mut sys, BOOT_FST_OFF_FIELD, (fst_off >> 2) as u32);
    put_u32(&mut sys, BOOT_FST_SIZE_FIELD, (fst_len >> 2) as u32);
    put_u32(&mut sys, BOOT_FST_MAX_FIELD, (fst_len >> 2) as u32);

    debug_assert_eq!(BOOT_BIN_LEN + BI2_LEN, APPLOADER_OFF);
    (sys, iso_off as u64)
}

fn pad_to(v: &mut Vec<u8>, len: usize) {
    if v.len() < len {
        v.resize(len, 0);
    }
}

fn write_title(dst: &mut [u8], title: &str) {
    let b = title.as_bytes();
    let n = b.len().min(dst.len() - 1);
    dst[..n].copy_from_slice(&b[..n]);
}

/// Build a minimal fakesigned Wii ticket (0x2A4 bytes). The title key is arbitrary — the NFS path
/// stores the disc already decrypted and never applies it (see [`crate::nfs`]).
fn build_wii_ticket(title_id: u64) -> Vec<u8> {
    let mut t = vec![0u8; TICKET_LEN];
    put_u32(&mut t, 0x000, WII_SIG_RSA2048_SHA1); // signature (0x004..0x104) left zero = fakesigned
    t[0x140..0x140 + 26].copy_from_slice(b"Root-CA00000001-XS00000003");
    // An arbitrary encrypted title key (value is a don't-care for the decrypted NFS path).
    t[0x1BF..0x1BF + 16].copy_from_slice(&[0xFE; 16]);
    t[0x1DC..0x1E4].copy_from_slice(&title_id.to_be_bytes());
    t[0x1F1] = 0; // common key index
    t
}

/// Build a minimal fakesigned Wii TMD (0x208 bytes) with a single content whose SHA-1 is the H3
/// table hash. `content_size` is the encrypted partition data size (clusters × 0x8000).
fn build_wii_tmd(title_id: u64, content_size: u64, h3_hash: &[u8; 20]) -> Vec<u8> {
    let mut m = vec![0u8; TMD_LEN];
    put_u32(&mut m, 0x000, WII_SIG_RSA2048_SHA1); // signature (0x004..0x104) left zero = fakesigned
    m[0x140..0x140 + 26].copy_from_slice(b"Root-CA00000001-CP00000004");
    m[0x18C..0x194].copy_from_slice(&title_id.to_be_bytes()); // title id
    m[0x1DE..0x1E0].copy_from_slice(&1u16.to_be_bytes()); // one content
                                                          // Content record 0 at 0x1E4: id, index, type, size, hash.
    put_u32(&mut m, 0x1E4, 0); // content id
    m[0x1E8..0x1EA].copy_from_slice(&0u16.to_be_bytes()); // index
    m[0x1EA..0x1EC].copy_from_slice(&1u16.to_be_bytes()); // type: normal
    m[0x1EC..0x1F4].copy_from_slice(&content_size.to_be_bytes());
    m[TMD_CONTENT0_HASH..TMD_CONTENT0_HASH + 20].copy_from_slice(h3_hash);
    m
}

/// The Nintendont-boot inputs for a synthetic disc (everything except the game image itself).
pub struct GcDiscInputs<'a> {
    /// Disc game id (6 bytes) — conventionally the GameCube game's id.
    pub game_id: [u8; 6],
    /// Disc title string (written into the disc/boot header).
    pub disc_title: &'a str,
    /// The `main.dol` to boot — Nintendont's `boot.dol`.
    pub main_dol: &'a [u8],
    /// The Wii apploader placed at partition-data offset 0x2440. May be empty for
    /// `nod`-validation builds (the apploader is hash-covered data `nod` never executes); a real
    /// apploader is only required to boot on hardware.
    pub apploader: &'a [u8],
    /// Title id recorded in the disc's Wii ticket/TMD (a don't-care for the decrypted NFS path).
    pub title_id: u64,
}

/// Author a synthetic Wii disc booting Nintendont, with `iso` (`iso_size` bytes) embedded as
/// `game.iso`. The disc is written to `out_path`; the returned [`AuthoredDisc`] borrows that file.
pub fn author_gc_disc(
    iso: &mut dyn ReadSeek,
    iso_size: u64,
    inputs: &GcDiscInputs,
    out_path: &Path,
) -> Result<AuthoredDisc> {
    let GcDiscInputs {
        game_id,
        disc_title,
        main_dol,
        apploader,
        title_id,
    } = *inputs;
    let ioerr = |e| Error::io(out_path, e);

    let (sys_blob, iso_off) = build_sys_blob(&game_id, disc_title, apploader, main_dol, iso_size);
    let logical_size = iso_off + iso_size;
    let total_clusters = logical_size.div_ceil(CLUSTER_DATA as u64) as usize;
    let num_groups = total_clusters.div_ceil(SECTORS_PER_GROUP);
    let data_size = total_clusters as u64 * SECTOR;

    let mut file = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(true)
        .open(out_path)
        .map_err(ioerr)?;

    // Write the data region first (the partition header needs the H3 table we compute here).
    file.seek(SeekFrom::Start(DATA_ABS)).map_err(ioerr)?;
    let mut h3_table = vec![0u8; H3_TABLE_SIZE];
    let mut group = vec![[0u8; DISC_SECTOR_SIZE]; SECTORS_PER_GROUP];

    for g in 0..num_groups {
        for (k, cluster) in group.iter_mut().enumerate() {
            cluster.fill(0);
            let ci = g * SECTORS_PER_GROUP + k;
            if ci < total_clusters {
                let logical_off = ci as u64 * CLUSTER_DATA as u64;
                fill_cluster_data(
                    &mut cluster[HASH_BLOCK..],
                    logical_off,
                    &sys_blob,
                    iso,
                    iso_off,
                    iso_size,
                )?;
            }
        }
        let h3 = recompute_group(&mut group);
        h3_table[g * 20..g * 20 + 20].copy_from_slice(&h3);
        for (k, cluster) in group.iter().enumerate() {
            if g * SECTORS_PER_GROUP + k < total_clusters {
                file.write_all(cluster).map_err(ioerr)?;
            }
        }
    }

    let content_hash: [u8; 20] = Sha1::digest(&h3_table).into();
    let ticket = build_wii_ticket(title_id);
    let tmd = build_wii_tmd(title_id, data_size, &content_hash);

    // Now build and write the 0x70000-byte prefix (disc header, partition table, partition
    // header) with the computed H3 table and TMD.
    let prefix = build_prefix(&game_id, disc_title, &ticket, &tmd, &h3_table, data_size);
    file.seek(SeekFrom::Start(0)).map_err(ioerr)?;
    file.write_all(&prefix).map_err(ioerr)?;
    file.flush().map_err(ioerr)?;

    let disc_size = DATA_ABS + total_clusters as u64 * SECTOR;
    let span = PartitionSpan {
        index: 0,
        start_sector: START_SECTOR,
        data_start_sector: DATA_START_SECTOR,
        data_end_sector: DATA_START_SECTOR + total_clusters as u32,
    };
    let plan = DiscPlan {
        partitions: vec![PartitionPlan {
            start_sector: span.start_sector,
            data_start_sector: span.data_start_sector,
            data_end_sector: span.data_end_sector,
            header_patches: Vec::new(),
            edits: Vec::new(),
        }],
        // The authored disc already has a single DATA partition and a matching table.
        disc_patches: Vec::new(),
        rvlt_content_hash: Some(content_hash),
        applied: Vec::new(),
    };

    Ok(AuthoredDisc {
        file,
        disc_size,
        spans: vec![span],
        plan,
        rvlt_ticket: ticket,
        rvlt_tmd: tmd,
    })
}

/// Fill one cluster's 0x7C00 data window (`dst`) starting at logical partition-data offset
/// `logical_off`, drawing from `sys_blob` (for `[0, iso_off)`) and the `iso` stream (for
/// `[iso_off, iso_off + iso_size)`). Bytes past the image end stay zero.
fn fill_cluster_data(
    dst: &mut [u8],
    logical_off: u64,
    sys_blob: &[u8],
    iso: &mut dyn ReadSeek,
    iso_off: u64,
    iso_size: u64,
) -> Result<()> {
    let start = logical_off;
    let end = start + dst.len() as u64;

    // System-area portion.
    if start < iso_off {
        let s = start as usize;
        let e = end.min(iso_off) as usize;
        let avail = sys_blob.len().min(e);
        if s < avail {
            let n = avail - s;
            dst[..n].copy_from_slice(&sys_blob[s..avail]);
        }
    }

    // game.iso portion.
    let iso_end = iso_off + iso_size;
    if end > iso_off && start < iso_end {
        let s = start.max(iso_off);
        let e = end.min(iso_end);
        if s < e {
            iso.seek(SeekFrom::Start(s - iso_off))
                .map_err(|err| Error::io("<game.iso>", err))?;
            let doff = (s - start) as usize;
            let n = (e - s) as usize;
            iso.read_exact(&mut dst[doff..doff + n])
                .map_err(|err| Error::io("<game.iso>", err))?;
        }
    }
    Ok(())
}

/// Build the 0x70000-byte disc prefix: disc header, partition table, region info, and the
/// partition header (ticket, header offset fields, TMD, and H3 table).
fn build_prefix(
    game_id: &[u8; 6],
    disc_title: &str,
    ticket: &[u8],
    tmd: &[u8],
    h3_table: &[u8],
    data_size: u64,
) -> Vec<u8> {
    let mut p = vec![0u8; DATA_ABS as usize];

    // Disc header.
    p[0..6].copy_from_slice(game_id);
    put_u32(&mut p, 0x18, DISC_MAGIC_WII);
    write_title(&mut p[0x20..0x20 + 0x40], disc_title);

    // Partition table: one group with one DATA partition.
    let pt = PARTITION_TABLE_ABS as usize;
    put_u32(&mut p, pt, 1); // group 0: one partition
    put_u32(&mut p, pt + 4, ((PARTITION_TABLE_ABS + 0x20) >> 2) as u32); // info table offset
    put_u32(&mut p, pt + 0x20, (PART_ABS >> 2) as u32); // partition offset
    put_u32(&mut p, pt + 0x24, 0); // type 0 = DATA

    // Region info (region code left 0).
    put_u32(&mut p, REGION_INFO_ABS as usize, 0);

    // Partition header.
    let ph = PART_ABS as usize;
    p[ph..ph + ticket.len()].copy_from_slice(ticket);
    put_u32(&mut p, ph + 0x2A4, tmd.len() as u32); // tmd_size
    put_u32(&mut p, ph + 0x2A8, (TMD_PART_OFF >> 2) as u32); // tmd_offset >> 2
    put_u32(&mut p, ph + 0x2AC, 0); // cert_chain_size (none)
    put_u32(&mut p, ph + 0x2B0, 0); // cert_chain_offset
    put_u32(&mut p, ph + 0x2B4, (H3_PART_OFF >> 2) as u32); // h3_table_offset >> 2
    put_u32(&mut p, ph + 0x2B8, (DATA_PART_OFF >> 2) as u32); // data_offset >> 2
    put_u32(&mut p, ph + 0x2BC, (data_size >> 2) as u32); // data_size >> 2
    let tmd_abs = ph + TMD_PART_OFF as usize;
    p[tmd_abs..tmd_abs + tmd.len()].copy_from_slice(tmd);
    let h3_abs = ph + H3_PART_OFF as usize;
    p[h3_abs..h3_abs + h3_table.len()].copy_from_slice(h3_table);

    p
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    /// Author a tiny synthetic disc (a few-cluster fake game.iso), pack it to NFS, reopen with
    /// `nod`'s hash **validation** on, and confirm: the partition traverses without a hash error,
    /// `main.dol` reads back as our Nintendont stand-in, `game.iso` extracts byte-identically via
    /// the FST, and the TMD content hash equals SHA1 of the rebuilt H3 table. This exercises the
    /// full authoring → build_nfs → nod pipeline offline.
    #[test]
    fn authored_disc_validates_and_round_trips_through_nod() {
        use crate::nfs::build_nfs;

        // Fake inputs.
        let iso: Vec<u8> = (0..200_000u32)
            .map(|i| (i.wrapping_mul(2654435761) >> 13) as u8)
            .collect();
        let main_dol: Vec<u8> = (0..4096u32).map(|i| (i ^ 0xA5) as u8).collect();
        let game_id = *b"GM2E8P";
        let title_id = 0x0005_0000_1234_5678u64;

        let out = tempfile::tempdir().unwrap();
        let disc_path = out.path().join("gc_disc.img");
        let mut cur = Cursor::new(iso.clone());
        let mut authored = author_gc_disc(
            &mut cur,
            iso.len() as u64,
            &GcDiscInputs {
                game_id,
                disc_title: "GC Test",
                main_dol: &main_dol,
                apploader: &[], // empty placeholder — nod never executes it
                title_id,
            },
            &disc_path,
        )
        .unwrap();

        // The disc's TMD content hash must equal SHA1(H3 table) — the invariant a Wii VC checks.
        let content_hash = authored.plan.rvlt_content_hash.unwrap();
        assert_eq!(
            &authored.rvlt_tmd[TMD_CONTENT0_HASH..TMD_CONTENT0_HASH + 20],
            content_hash.as_slice()
        );

        // Pack to NFS.
        let htk = [0x5Au8; 16];
        let nfs_dir = out.path().join("content");
        std::fs::create_dir_all(&nfs_dir).unwrap();
        let plan = authored.plan.clone();
        build_nfs(&mut authored, &htk, &nfs_dir, &plan).unwrap();
        std::fs::write(nfs_dir.join("htk.bin"), htk).unwrap();

        // Reopen with hash validation on.
        let nfs = nod::Disc::new_with_options(
            nfs_dir.join("hif_000000.nfs"),
            &nod::OpenOptions {
                rebuild_encryption: false,
                validate_hashes: true,
            },
        )
        .unwrap();
        assert!(nfs.header().is_wii());
        let mut part = nfs.open_partition_kind(nod::PartitionKind::Data).unwrap();

        // Read boot.bin, follow the DOL offset, and confirm main.dol reads back (validating the
        // clusters it spans as a side effect).
        let mut boot = [0u8; 0x440];
        part.seek(SeekFrom::Start(0)).unwrap();
        part.read_exact(&mut boot).unwrap();
        let dol_off = (u32::from_be_bytes(boot[0x420..0x424].try_into().unwrap()) as u64) << 2;
        let fst_off = (u32::from_be_bytes(boot[0x424..0x428].try_into().unwrap()) as u64) << 2;
        let mut dol_back = vec![0u8; main_dol.len()];
        part.seek(SeekFrom::Start(dol_off)).unwrap();
        part.read_exact(&mut dol_back).unwrap();
        assert_eq!(dol_back, main_dol, "main.dol must read back intact");

        // Parse the FST, find game.iso, extract and compare.
        let mut fst = [0u8; 12 * 2];
        part.seek(SeekFrom::Start(fst_off)).unwrap();
        part.read_exact(&mut fst).unwrap();
        let count = u32::from_be_bytes(fst[8..12].try_into().unwrap());
        assert_eq!(count, 2, "root FST entry count");
        let iso_data_off = (u32::from_be_bytes(fst[16..20].try_into().unwrap()) as u64) << 2;
        let iso_len = u32::from_be_bytes(fst[20..24].try_into().unwrap()) as usize;
        assert_eq!(iso_len, iso.len());
        let mut iso_back = vec![0u8; iso_len];
        part.seek(SeekFrom::Start(iso_data_off)).unwrap();
        part.read_exact(&mut iso_back).unwrap();
        assert_eq!(iso_back, iso, "game.iso must extract byte-identically");
    }

    /// Full-size end-to-end: author a synthetic disc from a real GameCube image, pack to NFS, and
    /// re-validate the whole partition through `nod` with hash validation on — then extract
    /// `game.iso` back and confirm it is byte-identical to the source image. This is the strongest
    /// offline proof; it reads/writes several GB. Uses `test_titles/Super Monkey Ball 2 (USA).rvz`.
    #[test]
    #[ignore = "reads a real GameCube image and writes multi-GB; run manually"]
    fn authors_real_gamecube_image_and_validates() {
        use crate::input::GcImage;
        use crate::nfs::build_nfs;

        let title = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../test_titles/Super Monkey Ball 2 (USA).rvz");
        if !title.exists() {
            eprintln!("skipping: {} not present", title.display());
            return;
        }

        let mut gc = GcImage::open(&title).unwrap();
        let iso_size = gc.iso_size();
        let game_id = gc.game_id();
        // Stand-in for Nintendont's boot.dol (the apploader question aside, nod validates
        // structure regardless of the DOL's contents).
        let main_dol: Vec<u8> = (0..8192u32).map(|i| (i ^ 0x5A) as u8).collect();

        let out = tempfile::tempdir().unwrap();
        let disc_path = out.path().join("gc_disc.img");
        let mut authored = author_gc_disc(
            gc.iso_stream(),
            iso_size,
            &GcDiscInputs {
                game_id,
                disc_title: "Super Monkey Ball 2",
                main_dol: &main_dol,
                apploader: &[],
                title_id: 0x0005_0000_1000_0000,
            },
            &disc_path,
        )
        .unwrap();

        let htk = [0x5Au8; 16];
        let nfs_dir = out.path().join("content");
        std::fs::create_dir_all(&nfs_dir).unwrap();
        let plan = authored.plan.clone();
        build_nfs(&mut authored, &htk, &nfs_dir, &plan).unwrap();
        std::fs::write(nfs_dir.join("htk.bin"), htk).unwrap();

        let nfs = nod::Disc::new_with_options(
            nfs_dir.join("hif_000000.nfs"),
            &nod::OpenOptions {
                rebuild_encryption: false,
                validate_hashes: true,
            },
        )
        .unwrap();
        let mut part = nfs.open_partition_kind(nod::PartitionKind::Data).unwrap();

        // Locate game.iso via the FST and stream it back, comparing to the source in chunks (any
        // hash-tree inconsistency raises an error on read).
        let mut boot = [0u8; 0x440];
        part.seek(SeekFrom::Start(0)).unwrap();
        part.read_exact(&mut boot).unwrap();
        let fst_off = (u32::from_be_bytes(boot[0x424..0x428].try_into().unwrap()) as u64) << 2;
        let mut fst = [0u8; 24];
        part.seek(SeekFrom::Start(fst_off)).unwrap();
        part.read_exact(&mut fst).unwrap();
        let iso_data_off = (u32::from_be_bytes(fst[16..20].try_into().unwrap()) as u64) << 2;
        let iso_len = u32::from_be_bytes(fst[20..24].try_into().unwrap()) as u64;
        assert_eq!(iso_len, iso_size, "FST records the full ISO size");

        part.seek(SeekFrom::Start(iso_data_off)).unwrap();
        let mut src = GcImage::open(&title).unwrap();
        let src_iso = src.iso_stream();
        src_iso.seek(SeekFrom::Start(0)).unwrap();
        let mut a = vec![0u8; 4 * 1024 * 1024];
        let mut b = vec![0u8; 4 * 1024 * 1024];
        let mut remaining = iso_size;
        while remaining > 0 {
            let n = remaining.min(a.len() as u64) as usize;
            part.read_exact(&mut a[..n]).unwrap();
            src_iso.read_exact(&mut b[..n]).unwrap();
            assert_eq!(
                &a[..n],
                &b[..n],
                "game.iso mismatch near {remaining} bytes left"
            );
            remaining -= n as u64;
        }
    }
}
