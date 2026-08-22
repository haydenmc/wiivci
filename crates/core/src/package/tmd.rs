//! The title metadata (`title.tmd`).
//!
//! Layout (big-endian), verified against a retail title:
//!
//! ```text
//! 0x000  u32 signature type (0x00010004, RSA-2048 SHA-256)
//! 0x004  0x100-byte signature (fakesigned: zero — accepted only with signature patches)
//! 0x104  padding to 0x140
//! 0x140  0x40 issuer  "Root-CA00000003-CP0000000b"
//! 0x180  header fields (version, system version, title id, title type, group id, …)
//! 0x1DE  u16 content count, u16 boot index, u16 reserved
//! 0x1E4  0x20 SHA-256 of the content-info table
//! 0x204  content-info table: 64 × 0x24 (entry 0 spans all contents; rest zero)
//! 0x0B04 content records: 0x30 each { u32 id, u16 index, u16 type, u64 size, 0x20 hash }
//! ```
//!
//! The per-content hash is a 20-byte SHA-1 zero-padded to 0x20 (of the `.h3` for hashed
//! content, or of the padded plaintext for non-hashed content).

use byteorder::{BigEndian, WriteBytesExt};
use sha2::{Digest, Sha256};

/// A single content record for the TMD.
#[derive(Clone, Debug)]
pub struct ContentRecord {
    /// Content id (matches the `.app` filename).
    pub id: u32,
    /// Content index.
    pub index: u16,
    /// Content type (0x2001 non-hashed, 0x2003 hashed).
    pub content_type: u16,
    /// Encrypted content size in bytes.
    pub size: u64,
    /// 20-byte SHA-1 recorded for this content.
    pub hash: [u8; 20],
}

/// Signature type used by fakesigned WUP titles: RSA-2048 SHA-256.
const SIG_TYPE_RSA2048_SHA256: u32 = 0x0001_0004;
const SIG_BLOCK: usize = 0x140;
const HEADER_END: usize = 0x1DE;
const INFO_TABLE_LEN: usize = 64 * 0x24;
const RECORDS_OFF: usize = 0x0B04;

/// The 0x140..0x1DE header region of a retail Wii-VC TMD. All fields are constant for titles
/// built on a Wii-VC base except the title id (@0x18C-0x140) and group id (@0x198-0x140),
/// which [`build_tmd`] patches. These describe the base framework (issuer, system version
/// 000500101000400A, title type 0x100, app type 0x8000002E), not the injected game.
const TMD_HEADER_TEMPLATE: [u8; HEADER_END - SIG_BLOCK] = [
    0x52, 0x6f, 0x6f, 0x74, 0x2d, 0x43, 0x41, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x33, 0x2d,
    0x43, 0x50, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x62, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x01, 0x00, 0x00, 0x00, 0x00, 0x05, 0x00, 0x10, 0x10, 0x00, 0x40, 0x0a, 0x00, 0x05, 0x00, 0x00,
    0x10, 0x1b, 0x07, 0x00, 0x00, 0x00, 0x01, 0x00, 0x1b, 0x07, 0x80, 0x00, 0x00, 0x2e, 0x00, 0x00,
    0x00, 0x00, 0x1d, 0xe6, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
];

// Offsets of the patchable fields within the header template.
const TITLE_ID_OFF: usize = 0x18C - SIG_BLOCK;
const GROUP_ID_OFF: usize = 0x198 - SIG_BLOCK;

/// Build a complete `title.tmd` for the given title id, group id and content records.
pub fn build_tmd(title_id: u64, group_id: u16, contents: &[ContentRecord]) -> Vec<u8> {
    // Content records.
    let mut records = Vec::with_capacity(contents.len() * 0x30);
    for c in contents {
        records.write_u32::<BigEndian>(c.id).unwrap();
        records.write_u16::<BigEndian>(c.index).unwrap();
        records.write_u16::<BigEndian>(c.content_type).unwrap();
        records.write_u64::<BigEndian>(c.size).unwrap();
        records.extend_from_slice(&c.hash);
        records.extend_from_slice(&[0u8; 12]); // pad SHA-1 to 0x20
    }

    // Content-info table: entry 0 spans all contents; the rest are zero.
    let mut info_table = vec![0u8; INFO_TABLE_LEN];
    info_table[0..2].copy_from_slice(&0u16.to_be_bytes()); // index offset
    info_table[2..4].copy_from_slice(&(contents.len() as u16).to_be_bytes()); // command count
    info_table[4..36].copy_from_slice(&Sha256::digest(&records));
    let info_hash = Sha256::digest(&info_table);

    let mut out = Vec::with_capacity(RECORDS_OFF + records.len());
    out.write_u32::<BigEndian>(SIG_TYPE_RSA2048_SHA256).unwrap();
    out.extend_from_slice(&[0u8; SIG_BLOCK - 4]); // fakesigned signature + padding

    let mut header = TMD_HEADER_TEMPLATE;
    header[TITLE_ID_OFF..TITLE_ID_OFF + 8].copy_from_slice(&title_id.to_be_bytes());
    header[GROUP_ID_OFF..GROUP_ID_OFF + 2].copy_from_slice(&group_id.to_be_bytes());
    out.extend_from_slice(&header);

    out.write_u16::<BigEndian>(contents.len() as u16).unwrap(); // content count
    out.write_u16::<BigEndian>(0).unwrap(); // boot index
    out.write_u16::<BigEndian>(0).unwrap(); // reserved
    out.extend_from_slice(&info_hash);
    out.extend_from_slice(&info_table);
    out.extend_from_slice(&records);

    debug_assert_eq!(out.len(), RECORDS_OFF + records.len());
    out
}

/// Parse the content records from a TMD's bytes.
pub fn parse_content_records(tmd: &[u8]) -> Result<Vec<ContentRecord>, &'static str> {
    if tmd.len() < RECORDS_OFF + 2 {
        return Err("TMD too short");
    }
    let count = u16::from_be_bytes([tmd[0x1DE], tmd[0x1DF]]) as usize;
    if tmd.len() < RECORDS_OFF + count * 0x30 {
        return Err("TMD content records truncated");
    }
    let mut records = Vec::with_capacity(count);
    for i in 0..count {
        let o = RECORDS_OFF + i * 0x30;
        let mut hash = [0u8; 20];
        hash.copy_from_slice(&tmd[o + 16..o + 36]);
        records.push(ContentRecord {
            id: u32::from_be_bytes(tmd[o..o + 4].try_into().unwrap()),
            index: u16::from_be_bytes(tmd[o + 4..o + 6].try_into().unwrap()),
            content_type: u16::from_be_bytes(tmd[o + 6..o + 8].try_into().unwrap()),
            size: u64::from_be_bytes(tmd[o + 8..o + 16].try_into().unwrap()),
            hash,
        });
    }
    Ok(records)
}

#[cfg(test)]
mod tests {
    use super::*;
    use byteorder::ReadBytesExt;
    use std::io::Cursor;

    #[test]
    fn tmd_structure_is_self_consistent() {
        let contents = vec![
            ContentRecord { id: 0, index: 0, content_type: 0x2001, size: 0x8000, hash: [1; 20] },
            ContentRecord { id: 1, index: 1, content_type: 0x2003, size: 0x10000, hash: [2; 20] },
        ];
        let tmd = build_tmd(0x0005000252535045, 0x5045, &contents);
        assert_eq!(&tmd[0x140..0x140 + 26], b"Root-CA00000003-CP0000000b");
        assert_eq!(&tmd[0x18C..0x194], &0x0005000252535045u64.to_be_bytes());
        let mut c = Cursor::new(&tmd[0x1DE..0x1E0]);
        assert_eq!(c.read_u16::<BigEndian>().unwrap(), 2); // content count
        // info table hash chain
        let info_hash = &tmd[0x1E4..0x204];
        assert_eq!(info_hash, Sha256::digest(&tmd[0x204..0x204 + INFO_TABLE_LEN]).as_slice());
        let records = &tmd[RECORDS_OFF..];
        assert_eq!(&tmd[0x208..0x228], Sha256::digest(records).as_slice());
    }

    /// Rebuild a retail TMD's body from its own content records and confirm we reproduce the
    /// header, info table and records byte-for-byte (the signature is fakesigned/zeroed, so
    /// only bytes from 0x140 onward are compared).
    #[test]
    fn reproduces_reference_tmd_body() {
        let path =
            std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../.dev/wup_ref/title.tmd");
        if !path.exists() {
            eprintln!("skipping: {} not present", path.display());
            return;
        }
        let reference = std::fs::read(&path).unwrap();
        let count = u16::from_be_bytes([reference[0x1DE], reference[0x1DF]]) as usize;
        let mut contents = Vec::with_capacity(count);
        for i in 0..count {
            let o = RECORDS_OFF + i * 0x30;
            let mut hash = [0u8; 20];
            hash.copy_from_slice(&reference[o + 16..o + 36]);
            contents.push(ContentRecord {
                id: u32::from_be_bytes(reference[o..o + 4].try_into().unwrap()),
                index: u16::from_be_bytes(reference[o + 4..o + 6].try_into().unwrap()),
                content_type: u16::from_be_bytes(reference[o + 6..o + 8].try_into().unwrap()),
                size: u64::from_be_bytes(reference[o + 8..o + 16].try_into().unwrap()),
                hash,
            });
        }
        let title_id = u64::from_be_bytes(reference[0x18C..0x194].try_into().unwrap());
        let group_id = u16::from_be_bytes([reference[0x198], reference[0x199]]);
        let ours = build_tmd(title_id, group_id, &contents);
        let end = RECORDS_OFF + count * 0x30;
        assert_eq!(&ours[0x140..], &reference[0x140..end], "TMD body differs from reference");
    }
}
