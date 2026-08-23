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
#[derive(Clone, Debug)]
pub struct EggsHeader {
    /// The LBA ranges describing which logical sectors are stored.
    pub ranges: Vec<LbaRange>,
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

    /// Total number of sectors covered by all ranges.
    pub fn total_sectors(&self) -> u64 {
        self.ranges.iter().map(|r| r.num_sectors as u64).sum()
    }

    /// Serialize to the fixed 0x200-byte header.
    pub fn to_bytes(&self) -> [u8; HEADER_SIZE] {
        let mut buf = [0u8; HEADER_SIZE];
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
        // trailer
        assert_eq!(&bytes[0x1FC..0x200], b"SGGE");
        assert_eq!(bytes.len(), 0x200);
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
