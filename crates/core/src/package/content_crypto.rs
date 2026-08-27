//! Content encryption and the H0–H3 hash tree.
//!
//! Two content encodings, both AES-128-CBC with the title key. All parameters below were
//! reverse-engineered from and verified byte-for-byte against a retail Wii U title.
//!
//! **Non-hashed** (content type `0x2001`): the payload is zero-padded to a 0x8000 multiple
//! and CBC-encrypted as one run with IV = `u16be(content_index) ++ 0*14`.
//!
//! **Hashed** (content type `0x2003`): the payload is split into 0xFC00 plaintext blocks.
//! Each output block is `0x400` encrypted hash header + `0xFC00` encrypted data:
//! * `H0[b] = SHA1(block b data)`; `H1`/`H2`/`H3` are SHA1 over the 0x140-byte hash section
//!   one level down; the `.h3` file is the concatenated H3 hashes.
//! * The hash header for a block carries the H0 section for its group of 16 blocks, the H1
//!   section for its super-group, and the H2 section for its H2-group, plus 0x40 padding.
//! * Hash levels are computed over the real (un-obfuscated) sections; then header byte 1 is
//!   XORed with the content index before the header is encrypted (IV = `u16be(index) ++ 0*14`).
//! * The data is encrypted with IV = the real `H0[b][0..16]`.

use std::io::{self, Cursor, Read, Write};

use aes::cipher::block_padding::UnpadError;
use aes::cipher::{block_padding::NoPadding, BlockDecryptMut, BlockEncryptMut, KeyIvInit};
use aes::Aes128;
use sha1::{Digest, Sha1};

use crate::error::{Error, Result};

/// Plaintext bytes per hashed block.
pub const HASH_BLOCK_DATA: usize = 0xFC00;
/// Total bytes per hashed output block (0x400 hash header + data).
pub const HASH_BLOCK_TOTAL: usize = 0x10000;
/// Size of the hash header prepended to each hashed block.
pub const HASH_HEADER: usize = 0x400;
/// Padding unit for non-hashed content.
pub const CONTENT_PADDING: usize = 0x8000;

/// Blocks per top-level H3 group. Must equal 16^3: the hash tree is 16-ary at every level, so one
/// H3 group spans exactly 16*16*16 blocks and every hash a block's header references lives inside
/// its own group. The streaming encoder relies on this to process one group at a time and still
/// produce byte-identical output — do not change it.
pub const HASH_GROUP_BLOCKS: usize = 4096;

const HASH_LEN: usize = 20;
const SECTION: usize = 16 * HASH_LEN; // 0x140: sixteen hashes per level section

type Key = [u8; 16];
type Hash = [u8; HASH_LEN];

fn sha1(data: &[u8]) -> Hash {
    let mut h = Sha1::new();
    h.update(data);
    h.finalize().into()
}

fn cbc_encrypt(key: &Key, iv: [u8; 16], buf: &mut [u8]) {
    let len = buf.len();
    <cbc::Encryptor<Aes128>>::new(key.into(), &iv.into())
        .encrypt_padded_mut::<NoPadding>(buf, len)
        .expect("block-aligned buffer");
}

/// Decrypt `buf` in place with AES-128-CBC (no padding). Errors (rather than panics) if
/// `buf.len()` is not a multiple of the AES block size (16) — reachable with a truncated or
/// otherwise corrupted ciphertext from an HTTP download or user-supplied file.
fn cbc_decrypt(key: &Key, iv: [u8; 16], buf: &mut [u8]) -> std::result::Result<(), UnpadError> {
    <cbc::Decryptor<Aes128>>::new(key.into(), &iv.into())
        .decrypt_padded_mut::<NoPadding>(buf)
        .map(|_| ())
}

fn content_iv(index: u16) -> [u8; 16] {
    let mut iv = [0u8; 16];
    iv[0..2].copy_from_slice(&index.to_be_bytes());
    iv
}

/// Round `n` up to the next multiple of `to`.
fn round_up(n: usize, to: usize) -> usize {
    n.div_ceil(to) * to
}

/// The result of encoding one content.
pub struct EncodedContent {
    /// The encrypted `.app` bytes.
    pub data: Vec<u8>,
    /// The `.h3` hash file, present only for hashed content.
    pub h3: Option<Vec<u8>>,
    /// The 20-byte SHA-1 recorded in the TMD (of the `.h3` for hashed content, or of the
    /// padded plaintext for non-hashed content).
    pub tmd_hash: Hash,
    /// The encrypted content size in bytes (goes in the TMD content record).
    pub size: u64,
}

/// Encrypt a non-hashed content (`0x2001`).
pub fn encode_nonhashed(key: &Key, index: u16, plaintext: &[u8]) -> EncodedContent {
    let mut buf = plaintext.to_vec();
    buf.resize(round_up(buf.len().max(1), CONTENT_PADDING), 0);
    let tmd_hash = sha1(&buf);
    cbc_encrypt(key, content_iv(index), &mut buf);
    let size = buf.len() as u64;
    EncodedContent {
        data: buf,
        h3: None,
        tmd_hash,
        size,
    }
}

/// Gather the 0x140-byte hash section for the 16 children starting at `base`, zero-filling
/// any that do not exist.
fn section(hashes: &[Hash], base: usize) -> Vec<u8> {
    let mut out = vec![0u8; SECTION];
    for j in 0..16 {
        if let Some(h) = hashes.get(base + j) {
            out[j * HASH_LEN..(j + 1) * HASH_LEN].copy_from_slice(h);
        }
    }
    out
}

/// The `.h3`, TMD hash, and encrypted size produced by streaming a hashed content to a writer.
pub struct HashedSummary {
    /// The `.h3` hash file (concatenated H3 hashes).
    pub h3: Vec<u8>,
    /// The 20-byte SHA-1 of the `.h3`, recorded in the TMD.
    pub tmd_hash: Hash,
    /// The encrypted content size in bytes.
    pub size: u64,
}

/// Read up to `buf.len()` bytes into `buf`, returning how many were filled (`< buf.len()` means the
/// reader hit EOF). `read` may return short, so loop until the buffer is full or EOF.
fn read_up_to<R: Read>(reader: &mut R, buf: &mut [u8]) -> io::Result<usize> {
    let mut filled = 0;
    while filled < buf.len() {
        let n = reader.read(&mut buf[filled..])?;
        if n == 0 {
            break;
        }
        filled += n;
    }
    Ok(filled)
}

/// Encrypt a hashed content (`0x2003`) by streaming `reader` to `writer` one H3 group
/// ([`HASH_GROUP_BLOCKS`] blocks ≈ 252 MiB) at a time, so peak memory is one group rather than the
/// whole content. Output is byte-identical to a whole-plaintext encode: every hash a block's header
/// references lives inside that block's own group (the tree is 16-ary and a group is 16^3 blocks),
/// so each group's hashes and ciphertext depend only on that group's plaintext.
pub fn encode_hashed_to_writer<R: Read, W: Write>(
    key: &Key,
    index: u16,
    mut reader: R,
    mut writer: W,
) -> io::Result<HashedSummary> {
    const GROUP_BYTES: usize = HASH_GROUP_BLOCKS * HASH_BLOCK_DATA;
    // Start with room for one block and grow (doubling, capped at GROUP_BYTES) only as the
    // content proves larger than the current buffer. This keeps peak allocation proportional to
    // the content's actual size instead of always reserving a full ~252 MiB group — a tiny
    // content (e.g. a 10 KB meta.xml) never grows the buffer past a block or two. Once a content
    // needs a full group the buffer settles at GROUP_BYTES and is reused as-is for every
    // subsequent group, exactly as before. Both the starting size and every doubled/capped size
    // stay exact multiples of HASH_BLOCK_DATA, which the block-slicing below relies on.
    let mut buf = vec![0u8; HASH_BLOCK_DATA];
    let mut h3: Vec<u8> = Vec::new();
    let mut size: u64 = 0;

    loop {
        let mut filled = read_up_to(&mut reader, &mut buf)?;
        while filled == buf.len() && buf.len() < GROUP_BYTES {
            let old_len = buf.len();
            let new_len = (old_len * 2).min(GROUP_BYTES);
            buf.resize(new_len, 0);
            filled += read_up_to(&mut reader, &mut buf[old_len..])?;
        }
        if filled == 0 && size > 0 {
            break; // clean EOF on a group boundary
        }
        // An empty content still encodes one zero block (matches nblocks.max(1)).
        let g = if filled == 0 {
            1
        } else {
            filled.div_ceil(HASH_BLOCK_DATA)
        };
        // Zero the tail of the last (possibly partial) block; the buffer is reused, so stale bytes
        // from a previous group could otherwise leak in.
        let used = g * HASH_BLOCK_DATA;
        if filled < used {
            buf[filled..used].fill(0);
        }

        // Local hash tree for this group only. G <= 16^3, so exactly one H3.
        let hl0: Vec<Hash> = (0..g)
            .map(|bl| sha1(&buf[bl * HASH_BLOCK_DATA..(bl + 1) * HASH_BLOCK_DATA]))
            .collect();
        let ngroups = g.div_ceil(16);
        let hl1: Vec<Hash> = (0..ngroups)
            .map(|gr| sha1(&section(&hl0, gr * 16)))
            .collect();
        let nsuper = ngroups.div_ceil(16);
        let hl2: Vec<Hash> = (0..nsuper).map(|s| sha1(&section(&hl1, s * 16))).collect();
        h3.extend_from_slice(&sha1(&section(&hl2, 0)));

        // Emit each block: real hash header (byte[1] obfuscated), then encrypted data.
        for bl in 0..g {
            let mut header = Vec::with_capacity(HASH_HEADER);
            header.extend_from_slice(&section(&hl0, (bl / 16) * 16));
            header.extend_from_slice(&section(&hl1, (bl / 256) * 16));
            header.extend_from_slice(&section(&hl2, 0));
            header.resize(HASH_HEADER, 0);
            header[1] ^= index as u8;
            cbc_encrypt(key, content_iv(index), &mut header);

            let mut data_iv = [0u8; 16];
            data_iv.copy_from_slice(&hl0[bl][..16]);
            let block = &mut buf[bl * HASH_BLOCK_DATA..(bl + 1) * HASH_BLOCK_DATA];
            cbc_encrypt(key, data_iv, block);

            writer.write_all(&header)?;
            writer.write_all(block)?;
            size += HASH_BLOCK_TOTAL as u64;
        }

        if filled < GROUP_BYTES {
            break; // this was the final (partial) group
        }
    }

    let tmd_hash = sha1(&h3);
    Ok(HashedSummary { h3, tmd_hash, size })
}

/// Encrypt a hashed content (`0x2003`) in memory, returning the ciphertext, `.h3`, and TMD hash.
/// Thin wrapper over [`encode_hashed_to_writer`] (in-memory `Vec`/`Cursor` I/O is infallible).
pub fn encode_hashed(key: &Key, index: u16, plaintext: &[u8]) -> EncodedContent {
    let mut data =
        Vec::with_capacity(plaintext.len().div_ceil(HASH_BLOCK_DATA).max(1) * HASH_BLOCK_TOTAL);
    let summary = encode_hashed_to_writer(key, index, Cursor::new(plaintext), &mut data)
        .expect("in-memory Vec I/O is infallible");
    EncodedContent {
        data,
        h3: Some(summary.h3),
        tmd_hash: summary.tmd_hash,
        size: summary.size,
    }
}

/// Decrypt a non-hashed content, returning the padded plaintext (inverse of
/// [`encode_nonhashed`]; the caller truncates to the real file size using the FST).
///
/// Errors (rather than panics) if `cipher`'s length is not a multiple of the AES block size
/// (16) — reachable from a truncated/corrupted HTTP download or user-supplied file.
pub fn decode_nonhashed(key: &Key, index: u16, cipher: &[u8]) -> Result<Vec<u8>> {
    let mut buf = cipher.to_vec();
    if !buf.is_empty() {
        cbc_decrypt(key, content_iv(index), &mut buf).map_err(|_| {
            Error::UnsupportedDisc(format!(
                "non-hashed content ciphertext length {} is not a multiple of the AES block size (16)",
                buf.len()
            ))
        })?;
    }
    Ok(buf)
}

/// Decrypt a hashed content, returning the concatenated 0xFC00 data blocks (inverse of
/// [`encode_hashed`]; hash headers are stripped).
///
/// Errors (rather than silently dropping a trailing partial block via floor division) if
/// `cipher`'s length is not an exact multiple of [`HASH_BLOCK_TOTAL`] (0x10000) — reachable from
/// a truncated/corrupted HTTP download or user-supplied file.
pub fn decode_hashed(key: &Key, index: u16, cipher: &[u8]) -> Result<Vec<u8>> {
    if !cipher.len().is_multiple_of(HASH_BLOCK_TOTAL) {
        return Err(Error::UnsupportedDisc(format!(
            "hashed content ciphertext length {} is not a multiple of the hashed block size (0x{HASH_BLOCK_TOTAL:x})",
            cipher.len()
        )));
    }
    let nblocks = cipher.len() / HASH_BLOCK_TOTAL;
    let mut out = Vec::with_capacity(nblocks * HASH_BLOCK_DATA);
    for b in 0..nblocks {
        let block = &cipher[b * HASH_BLOCK_TOTAL..(b + 1) * HASH_BLOCK_TOTAL];
        let mut header = block[..HASH_HEADER].to_vec();
        cbc_decrypt(key, content_iv(index), &mut header).map_err(|_| {
            Error::UnsupportedDisc(format!("decrypting hashed content block {b} header"))
        })?;
        header[1] ^= index as u8; // recover the real H0 section
        let mut data_iv = [0u8; 16];
        data_iv.copy_from_slice(&header[(b % 16) * HASH_LEN..(b % 16) * HASH_LEN + 16]);
        let mut data = block[HASH_HEADER..].to_vec();
        cbc_decrypt(key, data_iv, &mut data).map_err(|_| {
            Error::UnsupportedDisc(format!("decrypting hashed content block {b} data"))
        })?;
        out.extend_from_slice(&data);
    }
    Ok(out)
}

/// Recompute the SHA-1 TMD hash for a decoded non-hashed content: simply the hash of the padded
/// plaintext, matching what [`encode_nonhashed`] records.
pub fn nonhashed_tmd_hash(padded_plaintext: &[u8]) -> [u8; 20] {
    sha1(padded_plaintext)
}

/// Recompute the SHA-1 TMD hash for a decoded hashed content, without re-encrypting: rebuild the
/// `.h3` from `plaintext` (the concatenated data blocks [`decode_hashed`] returns) using the same
/// per-group hash-tree logic [`encode_hashed_to_writer`] uses when building, then hash that —
/// mirroring exactly what the TMD hash covers on the encode side (the `.h3`, not the ciphertext).
pub fn hashed_tmd_hash(plaintext: &[u8]) -> [u8; 20] {
    sha1(&compute_h3(plaintext))
}

/// Compute the `.h3` bytes for already-decoded hashed-content plaintext (concatenated
/// [`HASH_BLOCK_DATA`]-sized blocks), without any encryption. Groups blocks exactly as
/// [`encode_hashed_to_writer`] does — one H3 hash per up-to-[`HASH_GROUP_BLOCKS`] blocks — so for
/// data honestly produced by [`decode_hashed`] (always an exact multiple of [`HASH_BLOCK_DATA`])
/// the result is byte-identical to the `.h3` the encoder would have produced for the same
/// plaintext.
fn compute_h3(plaintext: &[u8]) -> Vec<u8> {
    const GROUP_BYTES: usize = HASH_GROUP_BLOCKS * HASH_BLOCK_DATA;
    let mut h3 = Vec::new();
    for group in plaintext.chunks(GROUP_BYTES) {
        let hl0: Vec<Hash> = group.chunks(HASH_BLOCK_DATA).map(sha1).collect();
        let ngroups = hl0.len().div_ceil(16);
        let hl1: Vec<Hash> = (0..ngroups)
            .map(|gr| sha1(&section(&hl0, gr * 16)))
            .collect();
        let nsuper = ngroups.div_ceil(16);
        let hl2: Vec<Hash> = (0..nsuper).map(|s| sha1(&section(&hl1, s * 16))).collect();
        h3.extend_from_slice(&sha1(&section(&hl2, 0)));
    }
    h3
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn nonhashed_pads_to_0x8000_and_hashes_padded() {
        let out = encode_nonhashed(&[0x11; 16], 5, b"hello");
        assert_eq!(out.size, 0x8000);
        assert_eq!(out.data.len(), 0x8000);
        assert!(out.h3.is_none());
    }

    #[test]
    fn hashed_block_count_and_h3_length() {
        // 2.5 data blocks -> 3 blocks -> 3*0x10000 bytes, one H3 hash.
        let plain = vec![0xABu8; HASH_BLOCK_DATA * 2 + 100];
        let out = encode_hashed(&[0x22; 16], 3, &plain);
        assert_eq!(out.size, 3 * HASH_BLOCK_TOTAL as u64);
        assert_eq!(out.h3.as_ref().unwrap().len(), HASH_LEN);
    }

    /// Verbatim copy of the original whole-plaintext hashed encoder, kept as an oracle to prove the
    /// streaming encoder is byte-identical across H3-group boundaries. Returns `(data, h3)`.
    fn reference_encode_hashed(key: &Key, index: u16, plaintext: &[u8]) -> (Vec<u8>, Vec<u8>) {
        let nblocks = plaintext.len().div_ceil(HASH_BLOCK_DATA).max(1);
        let mut h0 = Vec::with_capacity(nblocks);
        for b in 0..nblocks {
            let start = b * HASH_BLOCK_DATA;
            let mut block = vec![0u8; HASH_BLOCK_DATA];
            if start < plaintext.len() {
                let end = (start + HASH_BLOCK_DATA).min(plaintext.len());
                block[..end - start].copy_from_slice(&plaintext[start..end]);
            }
            h0.push(sha1(&block));
        }
        let ngroups = nblocks.div_ceil(16);
        let h1: Vec<Hash> = (0..ngroups).map(|g| sha1(&section(&h0, g * 16))).collect();
        let nsuper = ngroups.div_ceil(16);
        let h2: Vec<Hash> = (0..nsuper).map(|s| sha1(&section(&h1, s * 16))).collect();
        let nh3 = nsuper.div_ceil(16);
        let mut h3 = Vec::with_capacity(nh3 * HASH_LEN);
        for t in 0..nh3 {
            h3.extend_from_slice(&sha1(&section(&h2, t * 16)));
        }
        let mut data = Vec::with_capacity(nblocks * HASH_BLOCK_TOTAL);
        for b in 0..nblocks {
            let mut header = Vec::with_capacity(HASH_HEADER);
            header.extend_from_slice(&section(&h0, (b / 16) * 16));
            header.extend_from_slice(&section(&h1, (b / 256) * 16));
            header.extend_from_slice(&section(&h2, (b / 4096) * 16));
            header.resize(HASH_HEADER, 0);
            header[1] ^= index as u8;
            cbc_encrypt(key, content_iv(index), &mut header);
            let start = b * HASH_BLOCK_DATA;
            let mut block = vec![0u8; HASH_BLOCK_DATA];
            if start < plaintext.len() {
                let end = (start + HASH_BLOCK_DATA).min(plaintext.len());
                block[..end - start].copy_from_slice(&plaintext[start..end]);
            }
            let mut data_iv = [0u8; 16];
            data_iv.copy_from_slice(&h0[b][..16]);
            cbc_encrypt(key, data_iv, &mut block);
            data.extend_from_slice(&header);
            data.extend_from_slice(&block);
        }
        (data, h3)
    }

    /// The streaming encoder must be byte-identical to the whole-plaintext reference across an H3
    /// group boundary (spans 2 groups) and with a partial final block. ~258 MiB, so `#[ignore]`d.
    #[test]
    #[ignore = "encodes ~258 MiB; run manually to verify cross-group streaming equivalence"]
    fn streaming_matches_reference_across_groups() {
        let key = [0x9Cu8; 16];
        let index = 11u16;
        // 4097 blocks (one full H3 group + 1) plus a partial final block.
        let len = (HASH_GROUP_BLOCKS + 1) * HASH_BLOCK_DATA + 123;
        let plain: Vec<u8> = (0..len)
            .map(|i| i.wrapping_mul(31).wrapping_add(7) as u8)
            .collect();
        let streamed = encode_hashed(&key, index, &plain);
        let (ref_data, ref_h3) = reference_encode_hashed(&key, index, &plain);
        assert_eq!(
            streamed.data, ref_data,
            "ciphertext must match the reference"
        );
        assert_eq!(streamed.h3.unwrap(), ref_h3, ".h3 must match the reference");
        assert_eq!(streamed.tmd_hash, sha1(&ref_h3));
    }

    /// The group buffer now starts at one block and grows by doubling (capped at a full group)
    /// instead of always allocating a full ~252 MiB group up front — this keeps a small content
    /// (e.g. a 10 KB `meta.xml`) cheap. Exercise several growth steps (content spans multiple
    /// blocks, well under one group) and confirm the result still matches the whole-plaintext
    /// reference byte-for-byte. Cheap enough to run unconditionally.
    #[test]
    fn streaming_matches_reference_through_buffer_growth() {
        let key = [0x77u8; 16];
        let index = 5u16;
        // ~5 blocks: forces the buffer to double past 64 KiB, 128 KiB, 256 KiB while still being
        // tiny (well under the 252 MiB group cap).
        let len = 5 * HASH_BLOCK_DATA + 777;
        let plain: Vec<u8> = (0..len).map(|i| (i * 13) as u8).collect();
        let streamed = encode_hashed(&key, index, &plain);
        let (ref_data, ref_h3) = reference_encode_hashed(&key, index, &plain);
        assert_eq!(
            streamed.data, ref_data,
            "ciphertext must match the reference"
        );
        assert_eq!(streamed.h3.unwrap(), ref_h3, ".h3 must match the reference");
    }

    /// Also cover the exact-group-multiple boundary (no partial block, no partial group) cheaply is
    /// impossible (a group is 252 MiB), so this too is ignored: 2 full groups exactly.
    #[test]
    #[ignore = "encodes ~504 MiB; run manually"]
    fn streaming_matches_reference_exact_two_groups() {
        let key = [0x5Eu8; 16];
        let len = 2 * HASH_GROUP_BLOCKS * HASH_BLOCK_DATA; // exact multiple of group AND block
        let plain: Vec<u8> = (0..len).map(|i| (i >> 7) as u8).collect();
        let streamed = encode_hashed(&key, 4, &plain);
        let (ref_data, ref_h3) = reference_encode_hashed(&key, 4, &plain);
        assert_eq!(streamed.data, ref_data);
        assert_eq!(streamed.h3.unwrap(), ref_h3);
    }

    // --- Cross-validation against a retail package ------------------------------------
    // These require the extracted reference in .dev/wup_ref and the Wii U common key in the
    // WIIU_COMMON_KEY env var (never stored). Run:
    //   WIIU_COMMON_KEY=<hex> cargo test -p wiivci-core --release -- --ignored retail
    #[test]
    fn encode_decode_round_trips() {
        let key = [0x5Au8; 16];
        let plain: Vec<u8> = (0..HASH_BLOCK_DATA * 2 + 500)
            .map(|i| (i * 3) as u8)
            .collect();
        // Hashed: decode returns block-padded data, so compare only the original prefix.
        let enc = encode_hashed(&key, 7, &plain);
        let dec = decode_hashed(&key, 7, &enc.data).unwrap();
        assert_eq!(&dec[..plain.len()], &plain[..]);
        assert_eq!(
            hashed_tmd_hash(&dec),
            enc.tmd_hash,
            "recomputed .h3 hash must match"
        );
        // Non-hashed: decode returns the 0x8000-padded plaintext.
        let enc = encode_nonhashed(&key, 2, &plain);
        let dec = decode_nonhashed(&key, 2, &enc.data).unwrap();
        assert_eq!(&dec[..plain.len()], &plain[..]);
        assert_eq!(nonhashed_tmd_hash(&dec), enc.tmd_hash);
    }

    #[test]
    fn decode_nonhashed_rejects_non_block_aligned_input() {
        let key = [0x11u8; 16];
        // 17 bytes: not a multiple of the AES block size (16).
        let err = decode_nonhashed(&key, 0, &[0u8; 17]).unwrap_err();
        assert!(err.to_string().contains("AES block size"), "{err}");
    }

    #[test]
    fn decode_hashed_rejects_non_block_aligned_input() {
        let key = [0x11u8; 16];
        // One byte short of a full hashed block.
        let err = decode_hashed(&key, 0, &vec![0u8; HASH_BLOCK_TOTAL - 1]).unwrap_err();
        assert!(err.to_string().contains("hashed block size"), "{err}");
    }

    /// A flipped byte in a hashed content's plaintext must change the recomputed TMD hash — the
    /// verification path in `extract.rs::decode_content` relies on this to catch corruption.
    #[test]
    fn hashed_tmd_hash_detects_tampering() {
        let key = [0x33u8; 16];
        let plain: Vec<u8> = (0..HASH_BLOCK_DATA + 10).map(|i| (i * 7) as u8).collect();
        let enc = encode_hashed(&key, 9, &plain);
        let good = decode_hashed(&key, 9, &enc.data).unwrap();
        assert_eq!(hashed_tmd_hash(&good), enc.tmd_hash);

        let mut tampered = enc.data.clone();
        tampered[HASH_HEADER + 5] ^= 0xFF; // flip a byte inside the first block's ciphertext
        let bad = decode_hashed(&key, 9, &tampered).unwrap();
        assert_ne!(
            hashed_tmd_hash(&bad),
            enc.tmd_hash,
            "tampering must be detected"
        );
    }

    /// Same for non-hashed content: a flipped byte must change the recomputed TMD hash.
    #[test]
    fn nonhashed_tmd_hash_detects_tampering() {
        let key = [0x44u8; 16];
        let plain = b"hello world".to_vec();
        let enc = encode_nonhashed(&key, 4, &plain);
        let good = decode_nonhashed(&key, 4, &enc.data).unwrap();
        assert_eq!(nonhashed_tmd_hash(&good), enc.tmd_hash);

        let mut tampered = enc.data.clone();
        tampered[0] ^= 0xFF;
        let bad = decode_nonhashed(&key, 4, &tampered).unwrap();
        assert_ne!(
            nonhashed_tmd_hash(&bad),
            enc.tmd_hash,
            "tampering must be detected"
        );
    }

    fn ref_dir() -> std::path::PathBuf {
        std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../.dev/wup_ref")
    }

    fn retail_title_key() -> Option<Key> {
        let hex = std::env::var("WIIU_COMMON_KEY").ok()?;
        let common: Key = {
            let mut k = [0u8; 16];
            for (i, byte) in k.iter_mut().enumerate() {
                *byte = u8::from_str_radix(hex.trim().get(i * 2..i * 2 + 2)?, 16).ok()?;
            }
            k
        };
        let tik = std::fs::read(ref_dir().join("title.tik")).ok()?;
        let mut iv = [0u8; 16];
        iv[..8].copy_from_slice(&tik[0x1DC..0x1E4]);
        let mut tk = [0u8; 16];
        tk.copy_from_slice(&tik[0x1BF..0x1CF]);
        cbc_decrypt(&common, iv, &mut tk).ok()?;
        Some(tk)
    }

    #[test]
    #[ignore = "needs .dev/wup_ref and WIIU_COMMON_KEY"]
    fn retail_nonhashed_content0_matches() {
        let dir = ref_dir();
        let fst = match std::fs::read(dir.join("fst_decrypted.bin")) {
            Ok(f) => f,
            Err(_) => return,
        };
        let Some(tk) = retail_title_key() else { return };
        let reference = std::fs::read(dir.join("00000000.app")).unwrap();
        let out = encode_nonhashed(&tk, 0, &fst);
        assert_eq!(out.data, reference, "content0 ciphertext mismatch");
        assert_eq!(out.size, reference.len() as u64);
    }

    #[test]
    #[ignore = "needs .dev/wup_ref and WIIU_COMMON_KEY"]
    fn retail_hashed_content3_matches() {
        let dir = ref_dir();
        let enc = match std::fs::read(dir.join("00000003.app")) {
            Ok(f) => f,
            Err(_) => return,
        };
        let Some(tk) = retail_title_key() else { return };
        let h3_ref = std::fs::read(dir.join("00000003.h3")).unwrap();

        // Decrypt the retail hashed content back to plaintext, then re-encode: an exact
        // match proves both decode_hashed and encode_hashed against retail.
        let index = 3u16;
        let plaintext = decode_hashed(&tk, index, &enc).unwrap();
        assert_eq!(
            hashed_tmd_hash(&plaintext),
            sha1(&h3_ref),
            "recomputed TMD hash mismatch"
        );
        let out = encode_hashed(&tk, index, &plaintext);
        assert_eq!(out.h3.as_ref().unwrap(), &h3_ref, ".h3 mismatch");
        assert_eq!(out.data, enc, "hashed content ciphertext mismatch");
    }
}
