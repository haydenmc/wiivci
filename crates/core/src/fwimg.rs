//! Byte-pattern patches for the base title's `fw.img` (the vWii firmware image).
//!
//! A fakesigned title needs `fw.img`'s signature check neutered; a title that boots **homebrew**
//! (Nintendont, for GameCube injection) additionally needs AHBPROT and MEMPROT disabled so the
//! loaded DOL gets full hardware access. Each patch is a search-and-replace that is applied only
//! where its signature is found and skipped (with a warning) otherwise — the exact bytes vary by
//! base title and firmware version, so a missing pattern must never corrupt the image.
//!
//! The patterns mirror the Wii-VC homebrew patches used by `nfs2iso2nfs`/UWUVCI. They cannot be
//! verified in this repository (there is no `fw.img` fixture, and the effect is only observable on
//! hardware); they are applied defensively and logged.

use std::path::Path;

use crate::error::{Error, Result};

/// A single search-and-replace patch against `fw.img`.
pub struct BytePatch {
    /// Human-readable name for logging.
    pub name: &'static str,
    /// Byte signature to locate.
    pub find: &'static [u8],
    /// Offset within a match at which to write [`Self::write`].
    pub at: usize,
    /// Replacement bytes.
    pub write: &'static [u8],
    /// Apply at every match (`true`) or only the first (`false`).
    pub all: bool,
}

/// Fakesign patch: neuter the signature check (`20 07 23 A2` / `20 07 4B 0B` → set the following
/// byte to 0). Applied at every site, matching the existing Wii-path behaviour.
pub const FAKESIGN_A: BytePatch = BytePatch {
    name: "fakesign",
    find: &[0x20, 0x07, 0x23, 0xA2],
    at: 1,
    write: &[0x00],
    all: true,
};
pub const FAKESIGN_B: BytePatch = BytePatch {
    name: "fakesign(alt)",
    find: &[0x20, 0x07, 0x4B, 0x0B],
    at: 1,
    write: &[0x00],
    all: true,
};

/// Disable AHBPROT so homebrew gets full hardware access (`D0 0B 23 08 43 13 60 0B` → `46 C0`).
pub const AHBPROT: BytePatch = BytePatch {
    name: "AHBPROT-disable",
    find: &[0xD0, 0x0B, 0x23, 0x08, 0x43, 0x13, 0x60, 0x0B],
    at: 0,
    write: &[0x46, 0xC0],
    all: false,
};

/// Disable MEMPROT (`01 94 B5 00 4B 08 22 01` → the trailing `22 01` becomes `22 00`).
pub const MEMPROT: BytePatch = BytePatch {
    name: "MEMPROT-disable",
    find: &[0x01, 0x94, 0xB5, 0x00, 0x4B, 0x08, 0x22, 0x01],
    at: 6,
    write: &[0x22, 0x00],
    all: false,
};

/// The patch set for an ordinary (Wii) fakesigned title: both fakesign signature variants.
/// Bases differ in which one they use — Rhythm Heaven Fever, for instance, uses the `20 07 4B 0B`
/// variant — so we try both; a missing one is a no-op.
pub const FAKESIGN_PATCHES: &[BytePatch] = &[FAKESIGN_A, FAKESIGN_B];

/// The patch set for a homebrew-booting (Nintendont) title: fakesign + AHBPROT + MEMPROT.
pub const HOMEBREW_PATCHES: &[BytePatch] = &[FAKESIGN_A, FAKESIGN_B, AHBPROT, MEMPROT];

/// Apply `patches` to `data` in place, returning the names of the patches that matched. A patch
/// whose signature is absent is skipped (and, when `warn_missing`, logged).
pub fn apply_patches(
    data: &mut [u8],
    patches: &[BytePatch],
    warn_missing: bool,
) -> Vec<&'static str> {
    let mut applied = Vec::new();
    for p in patches {
        let mut hits = 0usize;
        let mut i = 0usize;
        while i + p.find.len() <= data.len() {
            if &data[i..i + p.find.len()] == p.find {
                let dst = i + p.at;
                data[dst..dst + p.write.len()].copy_from_slice(p.write);
                hits += 1;
                if !p.all {
                    break;
                }
                i += p.find.len();
            } else {
                i += 1;
            }
        }
        if hits > 0 {
            applied.push(p.name);
        } else if warn_missing {
            log::warn!("fw.img: pattern for '{}' not found; skipped", p.name);
        }
    }
    applied
}

/// Read `path`, apply `patches`, and write it back. Errors only on I/O; a title with no matching
/// patterns is left byte-identical.
pub fn patch_file(path: &Path, patches: &[BytePatch]) -> Result<Vec<&'static str>> {
    let mut data = std::fs::read(path).map_err(|e| Error::io(path, e))?;
    let applied = apply_patches(&mut data, patches, true);
    if !applied.is_empty() {
        std::fs::write(path, &data).map_err(|e| Error::io(path, e))?;
        log::info!("patched fw.img: {}", applied.join(", "));
    } else {
        log::warn!("fw.img: no patch patterns matched; title may not load");
    }
    Ok(applied)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fakesign_patches_every_site() {
        let mut data = vec![0u8; 32];
        data[4..8].copy_from_slice(&[0x20, 0x07, 0x23, 0xA2]);
        data[20..24].copy_from_slice(&[0x20, 0x07, 0x23, 0xA2]);
        let applied = apply_patches(&mut data, &[FAKESIGN_A], true);
        assert_eq!(applied, vec!["fakesign"]);
        assert_eq!(data[5], 0x00);
        assert_eq!(data[21], 0x00);
    }

    #[test]
    fn ahbprot_replaces_first_two_bytes_of_match() {
        let mut data = vec![0xFFu8; 16];
        data[3..11].copy_from_slice(&[0xD0, 0x0B, 0x23, 0x08, 0x43, 0x13, 0x60, 0x0B]);
        let applied = apply_patches(&mut data, &[AHBPROT], true);
        assert_eq!(applied, vec!["AHBPROT-disable"]);
        assert_eq!(&data[3..5], &[0x46, 0xC0]);
        // The rest of the matched region is untouched.
        assert_eq!(&data[5..11], &[0x23, 0x08, 0x43, 0x13, 0x60, 0x0B]);
    }

    #[test]
    fn memprot_clears_trailing_flag() {
        let mut data = vec![0u8; 16];
        data[0..8].copy_from_slice(&[0x01, 0x94, 0xB5, 0x00, 0x4B, 0x08, 0x22, 0x01]);
        let applied = apply_patches(&mut data, &[MEMPROT], true);
        assert_eq!(applied, vec!["MEMPROT-disable"]);
        assert_eq!(&data[6..8], &[0x22, 0x00]);
    }

    #[test]
    fn missing_pattern_is_skipped_not_applied() {
        let mut data = vec![0u8; 16];
        let applied = apply_patches(&mut data, &[AHBPROT], false);
        assert!(applied.is_empty());
        assert_eq!(data, vec![0u8; 16], "no bytes changed when pattern absent");
    }

    /// Against a real staged base `fw.img`, the Wii fakesign set must find a site (Rhythm Heaven
    /// Fever uses the `20 07 4B 0B` variant at 0x271EE). Guards the regression where only the
    /// `20 07 23 A2` variant was checked and the warning fired on a patchable base.
    #[test]
    #[ignore = "needs .dev/base/code/fw.img"]
    fn patches_real_base_fwimg() {
        let path =
            std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../.dev/base/code/fw.img");
        if !path.exists() {
            eprintln!("skipping: {} not present", path.display());
            return;
        }
        let mut data = std::fs::read(&path).unwrap();
        let applied = apply_patches(&mut data, FAKESIGN_PATCHES, true);
        assert!(
            !applied.is_empty(),
            "a real base fw.img must match at least one fakesign variant, got {applied:?}"
        );
    }

    #[test]
    fn first_match_only_when_not_all() {
        let mut data = vec![0u8; 32];
        data[0..8].copy_from_slice(&[0x01, 0x94, 0xB5, 0x00, 0x4B, 0x08, 0x22, 0x01]);
        data[16..24].copy_from_slice(&[0x01, 0x94, 0xB5, 0x00, 0x4B, 0x08, 0x22, 0x01]);
        apply_patches(&mut data, &[MEMPROT], true);
        assert_eq!(&data[6..8], &[0x22, 0x00], "first match patched");
        assert_eq!(&data[22..24], &[0x22, 0x01], "second match left alone");
    }
}
