//! Per-sector AES-128-CBC encryption for NFS data.
//!
//! Each 0x8000-byte logical sector is encrypted independently with:
//!
//! * key = the 16-byte `htk.bin` from the base title;
//! * IV  = `[0u8; 12] ++ big_endian_u32(logical_sector)`.
//!
//! This mirrors `nod`'s NFS *reader* (which decrypts with the identical key/IV scheme), so
//! output produced here round-trips back through `nod` to the original decrypted disc.

use aes::cipher::{block_padding::NoPadding, BlockEncryptMut, BlockDecryptMut, KeyIvInit};
use aes::Aes128;

/// Compute the CBC IV for a given logical sector.
#[inline]
fn sector_iv(logical_sector: u32) -> [u8; 16] {
    let mut iv = [0u8; 16];
    iv[12..16].copy_from_slice(&logical_sector.to_be_bytes());
    iv
}

/// Encrypt one logical sector in place. `buf.len()` must be a multiple of 16.
#[inline]
pub fn encrypt_sector(key: &[u8; 16], logical_sector: u32, buf: &mut [u8]) {
    let iv = sector_iv(logical_sector);
    let len = buf.len();
    <cbc::Encryptor<Aes128>>::new(key.into(), &iv.into())
        .encrypt_padded_mut::<NoPadding>(buf, len)
        .expect("NoPadding with block-aligned buffer never fails");
}

/// Decrypt one logical sector in place (inverse of [`encrypt_sector`]); used by tests.
#[inline]
pub fn decrypt_sector(key: &[u8; 16], logical_sector: u32, buf: &mut [u8]) {
    let iv = sector_iv(logical_sector);
    <cbc::Decryptor<Aes128>>::new(key.into(), &iv.into())
        .decrypt_padded_mut::<NoPadding>(buf)
        .expect("NoPadding with block-aligned buffer never fails");
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
