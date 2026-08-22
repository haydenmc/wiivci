//! Loading and validation of the user-supplied cryptographic keys.
//!
//! Following the convention of every existing injector, **no key is ever bundled** in the
//! binary or repository. The user supplies:
//!
//! * the **Wii common key** — used by [`nod`](crate::input) to decrypt Wii disc partitions;
//! * the **Wii U common key** — used to encrypt the generated title key in the WUP ticket.
//!
//! Both are validated against their well-known MD5 fingerprints so a wrong or truncated key
//! is rejected up front rather than producing a silently-broken package. The `htk.bin` NFS
//! key is *not* handled here — it is read verbatim from the base title (see
//! [`crate::nfs`]), since it ships in the clear inside every base's `code/` directory.

use md5::{Digest, Md5};

use crate::error::{Error, Result};

/// A raw 16-byte AES-128 key.
pub type Key = [u8; 16];

/// MD5 of the 16 raw bytes of the retail Wii common key.
const WII_COMMON_KEY_MD5: [u8; 16] = [
    0x8d, 0x1a, 0x2e, 0xbc, 0xd8, 0x2a, 0x34, 0x69, 0xb7, 0x7f, 0xac, 0xf1, 0x5d, 0x9c, 0x8e, 0x50,
];

/// MD5 of the 16 raw bytes of the retail Wii U common key.
const WIIU_COMMON_KEY_MD5: [u8; 16] = [
    0xa2, 0x43, 0xbc, 0x56, 0xda, 0x48, 0xbd, 0x4e, 0xb5, 0x5c, 0x72, 0x6e, 0xcd, 0x75, 0x8d, 0x49,
];

/// The Wii common key, validated against its known fingerprint.
#[derive(Clone)]
pub struct WiiCommonKey(pub Key);

/// The Wii U common key, validated against its known fingerprint.
#[derive(Clone)]
pub struct WiiUCommonKey(pub Key);

fn parse_key(name: &'static str, raw: &[u8]) -> Result<Key> {
    // Accept either a 16-byte binary blob or a 32-char ASCII hex string (with optional
    // surrounding whitespace), matching how users commonly store these.
    if raw.len() == 16 {
        let mut key = [0u8; 16];
        key.copy_from_slice(raw);
        return Ok(key);
    }
    let trimmed: Vec<u8> = raw.iter().copied().filter(|b| !b.is_ascii_whitespace()).collect();
    if trimmed.len() == 32 && trimmed.iter().all(|b| b.is_ascii_hexdigit()) {
        let s = std::str::from_utf8(&trimmed).expect("hex digits are utf-8");
        let mut key = [0u8; 16];
        for (i, byte) in key.iter_mut().enumerate() {
            *byte = u8::from_str_radix(&s[i * 2..i * 2 + 2], 16).expect("validated hex");
        }
        return Ok(key);
    }
    Err(Error::InvalidKey {
        name,
        reason: format!("expected 16 raw bytes or 32 hex chars, got {} bytes", raw.len()),
    })
}

fn md5(data: &[u8]) -> [u8; 16] {
    let mut hasher = Md5::new();
    hasher.update(data);
    hasher.finalize().into()
}

fn validate(name: &'static str, key: &Key, expected_md5: &[u8; 16]) -> Result<()> {
    if &md5(key) == expected_md5 {
        Ok(())
    } else {
        Err(Error::InvalidKey { name, reason: "MD5 fingerprint does not match the retail key".into() })
    }
}

impl WiiCommonKey {
    /// Parse and validate the Wii common key from raw bytes (binary or ASCII hex).
    pub fn parse(raw: &[u8]) -> Result<Self> {
        let key = parse_key("Wii common", raw)?;
        validate("Wii common", &key, &WII_COMMON_KEY_MD5)?;
        Ok(WiiCommonKey(key))
    }
}

impl WiiUCommonKey {
    /// Parse and validate the Wii U common key from raw bytes (binary or ASCII hex).
    pub fn parse(raw: &[u8]) -> Result<Self> {
        let key = parse_key("Wii U common", raw)?;
        validate("Wii U common", &key, &WIIU_COMMON_KEY_MD5)?;
        Ok(WiiUCommonKey(key))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // The retail key *values* are not committed; tests derive fingerprints dynamically so
    // they verify parsing/validation logic without embedding secrets.
    #[test]
    fn hex_and_binary_parse_identically() {
        let hex = b"000102030405060708090a0b0c0d0e0f";
        let bin = [0u8, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15];
        assert_eq!(parse_key("t", hex).unwrap(), bin);
        assert_eq!(parse_key("t", &bin).unwrap(), bin);
    }

    #[test]
    fn hex_with_whitespace_is_accepted() {
        let hex = b"00 01 02 03 04 05 06 07 08 09 0a 0b 0c 0d 0e 0f\n";
        assert_eq!(parse_key("t", hex).unwrap()[0], 0x00);
        assert_eq!(parse_key("t", hex).unwrap()[15], 0x0f);
    }

    #[test]
    fn wrong_length_is_rejected() {
        assert!(parse_key("t", b"deadbeef").is_err());
    }

    #[test]
    fn validation_matches_self() {
        let key = [0xABu8; 16];
        let fp = md5(&key);
        assert!(validate("t", &key, &fp).is_ok());
        assert!(validate("t", &key, &[0u8; 16]).is_err());
    }
}
