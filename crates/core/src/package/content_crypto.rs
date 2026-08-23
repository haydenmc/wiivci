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

use aes::cipher::{block_padding::NoPadding, BlockDecryptMut, BlockEncryptMut, KeyIvInit};
use aes::Aes128;
use sha1::{Digest, Sha1};

/// Plaintext bytes per hashed block.
pub const HASH_BLOCK_DATA: usize = 0xFC00;
/// Total bytes per hashed output block (0x400 hash header + data).
pub const HASH_BLOCK_TOTAL: usize = 0x10000;
/// Size of the hash header prepended to each hashed block.
pub const HASH_HEADER: usize = 0x400;
/// Padding unit for non-hashed content.
pub const CONTENT_PADDING: usize = 0x8000;

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

fn cbc_decrypt(key: &Key, iv: [u8; 16], buf: &mut [u8]) {
    <cbc::Decryptor<Aes128>>::new(key.into(), &iv.into())
        .decrypt_padded_mut::<NoPadding>(buf)
        .expect("block-aligned buffer");
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

/// Encrypt a hashed content (`0x2003`), returning the ciphertext, `.h3`, and TMD hash.
pub fn encode_hashed(key: &Key, index: u16, plaintext: &[u8]) -> EncodedContent {
    let nblocks = plaintext.len().div_ceil(HASH_BLOCK_DATA).max(1);

    // H0: one hash per data block (last block zero-padded to 0xFC00).
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

    // H1 over H0 sections (per group of 16 blocks), H2 over H1 sections, H3 over H2 sections.
    let ngroups = nblocks.div_ceil(16);
    let h1: Vec<Hash> = (0..ngroups).map(|g| sha1(&section(&h0, g * 16))).collect();
    let nsuper = ngroups.div_ceil(16);
    let h2: Vec<Hash> = (0..nsuper).map(|s| sha1(&section(&h1, s * 16))).collect();
    let nh3 = nsuper.div_ceil(16);
    let mut h3 = Vec::with_capacity(nh3 * HASH_LEN);
    for t in 0..nh3 {
        h3.extend_from_slice(&sha1(&section(&h2, t * 16)));
    }

    // Emit each block: real hash header (with byte[1] obfuscated), then encrypted data.
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

    let tmd_hash = sha1(&h3);
    let size = data.len() as u64;
    EncodedContent {
        data,
        h3: Some(h3),
        tmd_hash,
        size,
    }
}

/// Decrypt a non-hashed content, returning the padded plaintext (inverse of
/// [`encode_nonhashed`]; the caller truncates to the real file size using the FST).
pub fn decode_nonhashed(key: &Key, index: u16, cipher: &[u8]) -> Vec<u8> {
    let mut buf = cipher.to_vec();
    if !buf.is_empty() {
        cbc_decrypt(key, content_iv(index), &mut buf);
    }
    buf
}

/// Decrypt a hashed content, returning the concatenated 0xFC00 data blocks (inverse of
/// [`encode_hashed`]; hash headers are stripped).
pub fn decode_hashed(key: &Key, index: u16, cipher: &[u8]) -> Vec<u8> {
    let nblocks = cipher.len() / HASH_BLOCK_TOTAL;
    let mut out = Vec::with_capacity(nblocks * HASH_BLOCK_DATA);
    for b in 0..nblocks {
        let block = &cipher[b * HASH_BLOCK_TOTAL..(b + 1) * HASH_BLOCK_TOTAL];
        let mut header = block[..HASH_HEADER].to_vec();
        cbc_decrypt(key, content_iv(index), &mut header);
        header[1] ^= index as u8; // recover the real H0 section
        let mut data_iv = [0u8; 16];
        data_iv.copy_from_slice(&header[(b % 16) * HASH_LEN..(b % 16) * HASH_LEN + 16]);
        let mut data = block[HASH_HEADER..].to_vec();
        cbc_decrypt(key, data_iv, &mut data);
        out.extend_from_slice(&data);
    }
    out
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
        let dec = decode_hashed(&key, 7, &enc.data);
        assert_eq!(&dec[..plain.len()], &plain[..]);
        // Non-hashed: decode returns the 0x8000-padded plaintext.
        let enc = encode_nonhashed(&key, 2, &plain);
        let dec = decode_nonhashed(&key, 2, &enc.data);
        assert_eq!(&dec[..plain.len()], &plain[..]);
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
        cbc_decrypt(&common, iv, &mut tk);
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
        let plaintext = decode_hashed(&tk, index, &enc);
        let out = encode_hashed(&tk, index, &plaintext);
        assert_eq!(out.h3.as_ref().unwrap(), &h3_ref, ".h3 mismatch");
        assert_eq!(out.data, enc, "hashed content ciphertext mismatch");
    }
}
