//! Optional video patches applied to the Wii game's `main.dol`.
//!
//! Contrary to the "patch the firmware" framing these are often described with, the flicker
//! filter and dithering are set up by the *game's own code* (`GXSetCopyFilter` / the VI copy
//! filter coefficients), so the community-standard patches — as implemented by UWUVCI — are
//! find/replace edits on the extracted `main.dol`, not on `fw.img`. The exact byte patterns
//! and semantics below are taken verbatim from UWUVCI's `DeflickerDitheringRemover`
//! (<https://github.com/stuff-by-3-random-dudes/UWUVCI-AIO-WPF>).
//!
//! Applying an edit inside the disc means [`crate::disc_patch`] must relocate `main.dol`, patch
//! it, and rebuild the Wii partition hash tree over the affected clusters.

/// Which optional `main.dol` video patches to apply.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct VideoPatches {
    /// Remove the vertical (de)flicker filter entirely (sharper image).
    pub deflicker: bool,
    /// Halve the vertical filter strength instead of removing it (softer than `deflicker`).
    pub half_vfilter: bool,
    /// Remove framebuffer dithering (better colour accuracy).
    pub dithering: bool,
}

impl VideoPatches {
    /// Whether any patch is requested.
    pub fn any(&self) -> bool {
        self.deflicker || self.half_vfilter || self.dithering
    }
}

// ---------------------------------------------------------------------------
// Patterns (verbatim from UWUVCI's DeflickerDitheringRemover.cs)
// ---------------------------------------------------------------------------

/// Deflicker: match this 356-byte PowerPC routine and turn its final conditional branch
/// (`beq +0x40`) into an unconditional one, skipping the copy-filter setup. First match only.
/// (UWUVCI's source comments this as "252 bytes", but the literal is 356 and `.Length` is used.)
#[rustfmt::skip]
pub const DEFLICKER_PATTERN: [u8; 356] = [
    0x2C, 0x03, 0x00, 0x00, 0x41, 0x82, 0x00, 0xF8, 0x89, 0x04, 0x00, 0x00,
    0x38, 0x00, 0x00, 0x00, 0x89, 0x44, 0x00, 0x01, 0x38, 0x60, 0x00, 0x00,
    0x51, 0x00, 0x07, 0x3E, 0x88, 0xE4, 0x00, 0x06, 0x51, 0x40, 0x26, 0x36,
    0x89, 0x04, 0x00, 0x0C, 0x50, 0xE3, 0x07, 0x3E, 0x38, 0xE0, 0x00, 0x00,
    0x51, 0x07, 0x07, 0x3E, 0x89, 0x44, 0x00, 0x0D, 0x89, 0x64, 0x00, 0x07,
    0x39, 0x00, 0x00, 0x00, 0x51, 0x47, 0x26, 0x36, 0x89, 0x44, 0x00, 0x02,
    0x89, 0x24, 0x00, 0x12, 0x51, 0x63, 0x26, 0x36, 0x51, 0x40, 0x45, 0x2E,
    0x89, 0x44, 0x00, 0x0E, 0x51, 0x28, 0x07, 0x3E, 0x89, 0x24, 0x00, 0x13,
    0x51, 0x47, 0x45, 0x2E, 0x89, 0x44, 0x00, 0x03, 0x51, 0x28, 0x26, 0x36,
    0x89, 0x24, 0x00, 0x14, 0x51, 0x40, 0x64, 0x26, 0x89, 0x44, 0x00, 0x0F,
    0x51, 0x28, 0x45, 0x2E, 0x89, 0x24, 0x00, 0x15, 0x51, 0x47, 0x64, 0x26,
    0x89, 0x44, 0x00, 0x04, 0x89, 0x64, 0x00, 0x08, 0x51, 0x28, 0x64, 0x26,
    0x51, 0x40, 0x83, 0x1E, 0x89, 0x44, 0x00, 0x10, 0x89, 0x24, 0x00, 0x16,
    0x51, 0x63, 0x45, 0x2E, 0x89, 0x64, 0x00, 0x09, 0x51, 0x47, 0x83, 0x1E,
    0x89, 0x44, 0x00, 0x05, 0x51, 0x28, 0x83, 0x1E, 0x89, 0x24, 0x00, 0x11,
    0x51, 0x63, 0x64, 0x26, 0x89, 0x64, 0x00, 0x0A, 0x51, 0x40, 0xA2, 0x16,
    0x89, 0x44, 0x00, 0x0B, 0x51, 0x27, 0xA2, 0x16, 0x88, 0x84, 0x00, 0x17,
    0x39, 0x20, 0x00, 0x01, 0x51, 0x63, 0x83, 0x1E, 0x51, 0x43, 0xA2, 0x16,
    0x50, 0x88, 0xA2, 0x16, 0x51, 0x20, 0xC0, 0x0E, 0x39, 0x40, 0x00, 0x02,
    0x39, 0x20, 0x00, 0x03, 0x38, 0x80, 0x00, 0x04, 0x51, 0x43, 0xC0, 0x0E,
    0x51, 0x27, 0xC0, 0x0E, 0x50, 0x88, 0xC0, 0x0E, 0x48, 0x00, 0x00, 0x24,
    0x3D, 0x00, 0x01, 0x66, 0x3C, 0x60, 0x02, 0x66, 0x3C, 0xE0, 0x03, 0x66,
    0x3C, 0x80, 0x04, 0x66, 0x38, 0x08, 0x66, 0x66, 0x38, 0x63, 0x66, 0x66,
    0x38, 0xE7, 0x66, 0x66, 0x39, 0x04, 0x66, 0x66, 0x3D, 0x20, 0xCC, 0x01,
    0x39, 0x40, 0x00, 0x61, 0x99, 0x49, 0x80, 0x00, 0x2C, 0x05, 0x00, 0x00,
    0x38, 0x80, 0x00, 0x53, 0x39, 0x60, 0x00, 0x00, 0x90, 0x09, 0x80, 0x00,
    0x38, 0x00, 0x00, 0x54, 0x39, 0x80, 0x00, 0x00, 0x50, 0x8B, 0xC0, 0x0E,
    0x99, 0x49, 0x80, 0x00, 0x50, 0x0C, 0xC0, 0x0E, 0x90, 0x69, 0x80, 0x00,
    0x99, 0x49, 0x80, 0x00, 0x90, 0xE9, 0x80, 0x00, 0x99, 0x49, 0x80, 0x00,
    0x91, 0x09, 0x80, 0x00, 0x41, 0x82, 0x00, 0x40,
];

/// Replaces the last 4 bytes of [`DEFLICKER_PATTERN`] (`b +0x40` in place of `beq +0x40`).
pub const DEFLICKER_REPLACEMENT: [u8; 4] = [0x48, 0x00, 0x00, 0x40];

/// Dithering: match this 40-byte routine and write [`DITHERING_REPLACEMENT`] to the 4 bytes
/// *preceding* the match (an unconditional branch that skips the dithering setup). First match.
#[rustfmt::skip]
pub const DITHERING_PATTERN: [u8; 40] = [
    0x3C, 0x80, 0xCC, 0x01, 0x38, 0xA0, 0x00, 0x61, 0x38, 0x00, 0x00, 0x00,
    0x80, 0xC7, 0x02, 0x20, 0x50, 0x66, 0x17, 0x7A, 0x98, 0xA4, 0x80, 0x00,
    0x90, 0xC4, 0x80, 0x00, 0x90, 0xC7, 0x02, 0x20, 0xB0, 0x07, 0x00, 0x02,
    0x4E, 0x80, 0x00, 0x20,
];

/// Written 4 bytes before the [`DITHERING_PATTERN`] match.
pub const DITHERING_REPLACEMENT: [u8; 4] = [0x48, 0x00, 0x00, 0x28];

/// Half VFilter: the 7-tap VI vertical-filter coefficients. Replaced in place at *every*
/// occurrence with [`HALF_VFILTER_REPLACEMENT`], reducing (not removing) the filter.
pub const HALF_VFILTER_PATTERN: [u8; 7] = [0x08, 0x08, 0x0A, 0x0C, 0x0A, 0x08, 0x08];

/// Softened vertical-filter coefficients.
pub const HALF_VFILTER_REPLACEMENT: [u8; 7] = [0x04, 0x04, 0x10, 0x10, 0x10, 0x04, 0x04];

/// A single byte-level edit within `main.dol`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DolEdit {
    /// Byte offset within `main.dol` where `bytes` are written.
    pub offset: usize,
    /// Replacement bytes.
    pub bytes: Vec<u8>,
    /// Human-readable patch name (for logging).
    pub label: &'static str,
}

/// Find the first occurrence of `needle` in `haystack` at or after `from`.
fn find_from(haystack: &[u8], needle: &[u8], from: usize) -> Option<usize> {
    if needle.is_empty() || haystack.len() < needle.len() {
        return None;
    }
    (from..=haystack.len() - needle.len()).find(|&i| &haystack[i..i + needle.len()] == needle)
}

/// Compute the byte edits the requested `patches` produce on `dol`.
///
/// Mirrors UWUVCI's `DeflickerDitheringRemover`: deflicker and dithering apply to the first
/// match only; half-vfilter to every match. A requested patch whose pattern is absent is
/// logged and skipped (matching how these tools no-op on non-matching games).
pub fn find_dol_edits(dol: &[u8], patches: &VideoPatches) -> Vec<DolEdit> {
    let mut edits = Vec::new();

    if patches.deflicker {
        match find_from(dol, &DEFLICKER_PATTERN, 0) {
            Some(pos) => edits.push(DolEdit {
                offset: pos + DEFLICKER_PATTERN.len() - DEFLICKER_REPLACEMENT.len(),
                bytes: DEFLICKER_REPLACEMENT.to_vec(),
                label: "deflicker",
            }),
            None => log::warn!("deflicker: pattern not found in main.dol; skipping"),
        }
    }

    if patches.dithering {
        // UWUVCI starts scanning at index 8 so the 4 bytes preceding the match always exist.
        match find_from(dol, &DITHERING_PATTERN, 8) {
            Some(pos) => edits.push(DolEdit {
                offset: pos - 4,
                bytes: DITHERING_REPLACEMENT.to_vec(),
                label: "dithering",
            }),
            None => log::warn!("dithering: pattern not found in main.dol; skipping"),
        }
    }

    if patches.half_vfilter {
        let mut from = 0;
        let mut found = false;
        while let Some(pos) = find_from(dol, &HALF_VFILTER_PATTERN, from) {
            edits.push(DolEdit {
                offset: pos,
                bytes: HALF_VFILTER_REPLACEMENT.to_vec(),
                label: "half-vfilter",
            });
            found = true;
            from = pos + HALF_VFILTER_PATTERN.len();
        }
        if !found {
            log::warn!("half-vfilter: pattern not found in main.dol; skipping");
        }
    }

    edits
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn deflicker_replaces_last_four_bytes_of_first_match() {
        let mut dol = vec![0u8; 32];
        dol.extend_from_slice(&DEFLICKER_PATTERN);
        dol.extend_from_slice(&[0xAAu8; 16]);
        // A second occurrence should be ignored (first match only).
        dol.extend_from_slice(&DEFLICKER_PATTERN);

        let edits = find_dol_edits(
            &dol,
            &VideoPatches {
                deflicker: true,
                ..Default::default()
            },
        );
        assert_eq!(edits.len(), 1);
        assert_eq!(edits[0].offset, 32 + DEFLICKER_PATTERN.len() - 4);
        assert_eq!(edits[0].bytes, DEFLICKER_REPLACEMENT);
        // The last 4 bytes of the pattern are the conditional branch we neutralise.
        assert_eq!(&DEFLICKER_PATTERN[352..], &[0x41, 0x82, 0x00, 0x40]);
    }

    #[test]
    fn dithering_writes_four_bytes_before_the_match() {
        let mut dol = vec![0x11u8; 100];
        let at = 60;
        dol[at..at + DITHERING_PATTERN.len()].copy_from_slice(&DITHERING_PATTERN);

        let edits = find_dol_edits(
            &dol,
            &VideoPatches {
                dithering: true,
                ..Default::default()
            },
        );
        assert_eq!(edits.len(), 1);
        assert_eq!(edits[0].offset, at - 4);
        assert_eq!(edits[0].bytes, DITHERING_REPLACEMENT);
    }

    #[test]
    fn half_vfilter_replaces_every_occurrence() {
        let mut dol = Vec::new();
        dol.extend_from_slice(&[0u8; 8]);
        dol.extend_from_slice(&HALF_VFILTER_PATTERN);
        dol.extend_from_slice(&[0u8; 5]);
        dol.extend_from_slice(&HALF_VFILTER_PATTERN);

        let edits = find_dol_edits(
            &dol,
            &VideoPatches {
                half_vfilter: true,
                ..Default::default()
            },
        );
        assert_eq!(edits.len(), 2);
        assert_eq!(edits[0].offset, 8);
        assert_eq!(edits[1].offset, 8 + 7 + 5);
        assert!(edits.iter().all(|e| e.bytes == HALF_VFILTER_REPLACEMENT));
    }

    #[test]
    fn missing_pattern_is_skipped_not_errored() {
        let dol = vec![0x00u8; 1000];
        let edits = find_dol_edits(
            &dol,
            &VideoPatches {
                deflicker: true,
                half_vfilter: true,
                dithering: true,
            },
        );
        assert!(edits.is_empty());
    }

    #[test]
    fn no_patches_yields_no_edits() {
        let dol = vec![0u8; 10];
        assert!(find_dol_edits(&dol, &VideoPatches::default()).is_empty());
        assert!(!VideoPatches::default().any());
    }
}
