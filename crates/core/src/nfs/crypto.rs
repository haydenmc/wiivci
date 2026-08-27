//! Per-sector AES-128-CBC encryption for NFS data.
//!
//! Each 0x8000-byte logical sector is encrypted independently with:
//!
//! * key = the 16-byte `htk.bin` from the base title;
//! * IV  = `[0u8; 12] ++ big_endian_u32(logical_sector)`.
//!
//! This mirrors `nod`'s NFS *reader* (which decrypts with the identical key/IV scheme), so
//! output produced here round-trips back through `nod` to the original decrypted disc.

use crate::aes_cbc;

/// Compute the CBC IV for a given logical sector.
#[inline]
fn sector_iv(logical_sector: u32) -> [u8; 16] {
    let mut iv = [0u8; 16];
    iv[12..16].copy_from_slice(&logical_sector.to_be_bytes());
    iv
}

/// Encrypt one logical sector in place.
///
/// `buf.len()` must be a multiple of the 16-byte AES block — every caller passes a whole
/// [`crate::input::DISC_SECTOR_SIZE`] sector. The invariant is checked by `debug_assert` in test
/// builds; in release only the block-aligned prefix (`len & !15`) is transformed and any trailing
/// partial block is left untouched, so a mis-sized buffer degrades instead of panicking (CBC with
/// `NoPadding` errors on a ragged length, and the old `.expect()` turned that into a panic).
#[inline]
pub fn encrypt_sector(key: &[u8; 16], logical_sector: u32, buf: &mut [u8]) {
    debug_assert_eq!(
        buf.len() % BLOCK,
        0,
        "NFS sector buffers must be a whole number of AES blocks"
    );
    let iv = sector_iv(logical_sector);
    let len = aligned_len(buf);
    if aes_cbc::encrypt(key, iv, &mut buf[..len]).is_err() {
        debug_assert!(false, "NoPadding on a block-aligned buffer cannot fail");
    }
}

/// Decrypt one logical sector in place (inverse of [`encrypt_sector`]); used by tests. Same
/// length invariant and guard as [`encrypt_sector`].
#[inline]
pub fn decrypt_sector(key: &[u8; 16], logical_sector: u32, buf: &mut [u8]) {
    debug_assert_eq!(
        buf.len() % BLOCK,
        0,
        "NFS sector buffers must be a whole number of AES blocks"
    );
    let iv = sector_iv(logical_sector);
    let len = aligned_len(buf);
    if aes_cbc::decrypt(key, iv, &mut buf[..len]).is_err() {
        debug_assert!(false, "NoPadding on a block-aligned buffer cannot fail");
    }
}

/// AES block size; sector buffers must be a multiple of this.
const BLOCK: usize = 16;

/// Length of the leading whole-AES-block region of `buf` (equal to `buf.len()` for every real
/// caller, which always passes a full sector).
#[inline]
fn aligned_len(buf: &[u8]) -> usize {
    buf.len() & !(BLOCK - 1)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn iv_places_sector_in_low_bytes_big_endian() {
        assert_eq!(sector_iv(0), [0u8; 16]);
        let iv = sector_iv(0x1F00);
        assert_eq!(&iv[0..12], &[0u8; 12]);
        assert_eq!(&iv[12..16], &[0x00, 0x00, 0x1F, 0x00]);
        assert_eq!(&sector_iv(1)[12..16], &[0, 0, 0, 1]);
    }

    #[test]
    fn encrypt_decrypt_round_trips() {
        let key = [0x11u8; 16];
        let original: Vec<u8> = (0..0x8000).map(|i| (i * 7) as u8).collect();
        let mut buf = original.clone();
        encrypt_sector(&key, 42, &mut buf);
        assert_ne!(buf, original);
        decrypt_sector(&key, 42, &mut buf);
        assert_eq!(buf, original);
    }

    /// A buffer that is not a whole number of AES blocks must not panic: the ragged tail is left
    /// untouched. Only meaningful with `debug_assertions` off (the `debug_assert` fires first in a
    /// debug build), which is how the gates run these tests (`cargo test --release`).
    #[test]
    #[cfg(not(debug_assertions))]
    fn ragged_buffer_does_not_panic_and_leaves_tail_untouched() {
        let key = [0x33u8; 16];
        let mut buf = [0xAAu8; 20]; // one whole block + 4 bytes
        encrypt_sector(&key, 7, &mut buf);
        assert_ne!(&buf[..16], &[0xAAu8; 16], "the whole block is encrypted");
        assert_eq!(&buf[16..], &[0xAAu8; 4], "the ragged tail is untouched");
        decrypt_sector(&key, 7, &mut buf);
        assert_eq!(buf, [0xAAu8; 20]);
    }

    #[test]
    fn different_sectors_produce_different_ciphertext() {
        let key = [0x22u8; 16];
        let plain = [0u8; 32];
        let mut a = plain;
        let mut b = plain;
        encrypt_sector(&key, 1, &mut a);
        encrypt_sector(&key, 2, &mut b);
        assert_ne!(a, b, "IV differs by sector so ciphertext must differ");
    }
}
