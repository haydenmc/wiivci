//! Shared AES-128-CBC (`NoPadding`) primitives.
//!
//! Both the NFS per-sector encoder ([`crate::nfs::crypto`]) and the WUP content encoder
//! ([`crate::package::content_crypto`]) drive the same `cbc`/`aes` cipher construction with
//! `NoPadding`, differing only in how each wraps the result (the NFS side degrades a mis-sized
//! buffer via `debug_assert` + an aligned-prefix guard, since it is invoked with values it fully
//! controls; the content side propagates a `Result`, since it decodes untrusted/possibly-corrupt
//! input). This module holds only the identical cipher call; callers keep their own
//! error-handling semantics on top.

use aes::cipher::block_padding::{NoPadding, UnpadError};
use aes::cipher::inout::PadError;
use aes::cipher::{BlockDecryptMut, BlockEncryptMut, KeyIvInit};
use aes::Aes128;

pub(crate) type Key = [u8; 16];

/// Encrypt `buf` in place with AES-128-CBC/NoPadding using `key`/`iv`.
///
/// `buf.len()` must be a multiple of the 16-byte AES block, or this returns `Err` (NoPadding
/// cannot pad a ragged length). Callers decide how to handle that.
#[inline]
pub(crate) fn encrypt(key: &Key, iv: [u8; 16], buf: &mut [u8]) -> Result<(), PadError> {
    let len = buf.len();
    <cbc::Encryptor<Aes128>>::new(key.into(), &iv.into())
        .encrypt_padded_mut::<NoPadding>(buf, len)
        .map(|_| ())
}

/// Decrypt `buf` in place with AES-128-CBC/NoPadding using `key`/`iv`. Same length invariant as
/// [`encrypt`].
#[inline]
pub(crate) fn decrypt(key: &Key, iv: [u8; 16], buf: &mut [u8]) -> Result<(), UnpadError> {
    <cbc::Decryptor<Aes128>>::new(key.into(), &iv.into())
        .decrypt_padded_mut::<NoPadding>(buf)
        .map(|_| ())
}
