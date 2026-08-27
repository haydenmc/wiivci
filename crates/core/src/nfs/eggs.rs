//! The EGGS header that prefixes `hif_000000.nfs`.
//!
//! Layout (0x200 bytes, big-endian), matching `nod`'s NFS reader:
//!
//! ```text
//! 0x000  magic          "EGGS"
//! 0x004  version        0x00011011
//! 0x008  unk1           0
//! 0x00C  unk2           0
//! 0x010  num_lba_ranges u32
//! 0x014  lba_ranges[61] { start_sector: u32, num_sectors: u32 }
//! 0x1FC  end_magic      "SGGE"
//! ```
//!
//! Sectors not covered by any LBA range are implicit runs of zeros — this is how the
//! format stores a multi-GB disc image sparsely.
//!
//! **Unused LBA-range slots must be filled with `0xFF`, not `0x00`.** The Wii U's `fw.img`
//! treats `0xFFFFFFFF` as the range-table terminator when it mounts the disc at boot; a `0x00`
//! fill reads as a bogus `{start: 0, num: 0}` range and hangs the emulator. (`nod`'s reader uses
//! `num_lba_ranges` and is lenient about the fill, so a `0x00`-padded header still round-trips —
//! it just won't boot on hardware. This bit us: installs fine, hangs on launch.)

use byteorder::{BigEndian, WriteBytesExt};

use crate::error::{Error, Result};

/// Size of the EGGS header in bytes.
pub const HEADER_SIZE: usize = 0x200;
/// EGGS header version written by injectors.
pub const VERSION: u32 = 0x0001_1011;
/// Maximum number of LBA ranges the header can hold.
pub const MAX_RANGES: usize = 61;

const MAGIC: &[u8; 4] = b"EGGS";
const END_MAGIC: &[u8; 4] = b"SGGE";

/// A contiguous run of logical disc sectors present in the NFS data.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct LbaRange {
    /// First logical sector of the run.
    pub start_sector: u32,
    /// Number of sectors in the run.
    pub num_sectors: u32,
}

/// The parsed/constructed EGGS header.
///
/// `ranges` is private so [`EggsHeader::new`]'s [`MAX_RANGES`] check cannot be bypassed by
/// pushing onto the vec afterwards — the header has room for exactly 61 slots, and an
/// over-long list would overrun the fixed 0x200-byte buffer in [`EggsHeader::to_bytes`].
#[derive(Clone, Debug)]
pub struct EggsHeader {
    /// The LBA ranges describing which logical sectors are stored.
    ranges: Vec<LbaRange>,
}

impl EggsHeader {
    /// Construct a header from a set of ranges, rejecting more than [`MAX_RANGES`].
    pub fn new(ranges: Vec<LbaRange>) -> Result<Self> {
        if ranges.len() > MAX_RANGES {
            return Err(Error::FormatLimit(format!(
                "NFS supports at most {MAX_RANGES} LBA ranges, got {}",
                ranges.len()
            )));
        }
        Ok(EggsHeader { ranges })
    }

    /// The LBA ranges this header describes, in the order they are serialized.
    pub fn ranges(&self) -> &[LbaRange] {
        &self.ranges
    }

    /// Total number of sectors covered by all ranges.
    pub fn total_sectors(&self) -> u64 {
        self.ranges.iter().map(|r| r.num_sectors as u64).sum()
    }

    /// Serialize to the fixed 0x200-byte header.
    pub fn to_bytes(&self) -> [u8; HEADER_SIZE] {
        let mut buf = [0u8; HEADER_SIZE];
        // Unused LBA-range slots must read as 0xFF (the terminator fw.img expects); fill the whole
        // range-table region first, then overwrite the used slots below.
        const RANGES_OFF: usize = 0x14;
        buf[RANGES_OFF..HEADER_SIZE - 4].fill(0xFF);
        {
            let mut cursor = &mut buf[..];
            cursor.write_all(MAGIC).unwrap();
            cursor.write_u32::<BigEndian>(VERSION).unwrap();
            cursor.write_u32::<BigEndian>(0).unwrap(); // unk1
            cursor.write_u32::<BigEndian>(0).unwrap(); // unk2
            cursor
                .write_u32::<BigEndian>(self.ranges.len() as u32)
                .unwrap();
            for range in &self.ranges {
                cursor.write_u32::<BigEndian>(range.start_sector).unwrap();
                cursor.write_u32::<BigEndian>(range.num_sectors).unwrap();
            }
        }
        buf[HEADER_SIZE - 4..].copy_from_slice(END_MAGIC);
        buf
    }
}

use std::io::Write;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn header_layout_is_correct() {
        let header = EggsHeader::new(vec![
            LbaRange {
                start_sector: 0,
                num_sectors: 1,
            },
            LbaRange {
                start_sector: 8,
                num_sectors: 2,
            },
            LbaRange {
                start_sector: 10,
                num_sectors: 0x1234,
            },
        ])
        .unwrap();
        let bytes = header.to_bytes();

        assert_eq!(&bytes[0..4], b"EGGS");
        assert_eq!(&bytes[4..8], &[0x00, 0x01, 0x10, 0x11]);
        assert_eq!(&bytes[8..12], &[0, 0, 0, 0]);
        assert_eq!(&bytes[12..16], &[0, 0, 0, 0]);
        assert_eq!(&bytes[16..20], &[0, 0, 0, 3]); // num ranges
                                                   // range 0
        assert_eq!(&bytes[20..24], &[0, 0, 0, 0]);
        assert_eq!(&bytes[24..28], &[0, 0, 0, 1]);
        // range 1
        assert_eq!(&bytes[28..32], &[0, 0, 0, 8]);
        assert_eq!(&bytes[32..36], &[0, 0, 0, 2]);
        // range 2
        assert_eq!(&bytes[36..40], &[0, 0, 0, 10]);
        assert_eq!(&bytes[40..44], &[0, 0, 0x12, 0x34]);
        // unused range slots are 0xFF-filled (the terminator fw.img expects), up to the trailer.
        assert_eq!(&bytes[44..48], &[0xFF, 0xFF, 0xFF, 0xFF]);
        assert!(bytes[44..0x1FC].iter().all(|&b| b == 0xFF));
        // trailer
        assert_eq!(&bytes[0x1FC..0x200], b"SGGE");
        assert_eq!(bytes.len(), 0x200);
    }

    /// The cap is exact: 61 ranges fill the table right up to the `SGGE` trailer, and the
    /// accessor hands back what was constructed (the field itself is private, so nothing can push
    /// past the cap afterwards).
    #[test]
    fn exactly_max_ranges_fills_the_table_up_to_the_trailer() {
        let ranges = vec![
            LbaRange {
                start_sector: 1,
                num_sectors: 2
            };
            MAX_RANGES
        ];
        let header = EggsHeader::new(ranges.clone()).unwrap();
        assert_eq!(header.ranges(), ranges.as_slice());
        assert_eq!(header.total_sectors(), 2 * MAX_RANGES as u64);

        let bytes = header.to_bytes();
        assert_eq!(&bytes[16..20], &[0, 0, 0, MAX_RANGES as u8]);
        const RANGES_OFF: usize = 0x14;
        assert_eq!(RANGES_OFF + MAX_RANGES * 8, HEADER_SIZE - 4);
        assert_eq!(
            &bytes[HEADER_SIZE - 12..HEADER_SIZE - 4],
            &[0, 0, 0, 1, 0, 0, 0, 2],
            "last slot sits immediately before the trailer"
        );
        assert_eq!(&bytes[HEADER_SIZE - 4..], b"SGGE");
    }

    #[test]
    fn too_many_ranges_rejected() {
        let ranges = vec![
            LbaRange {
                start_sector: 0,
                num_sectors: 1
            };
            MAX_RANGES + 1
        ];
        assert!(EggsHeader::new(ranges).is_err());
    }
}
