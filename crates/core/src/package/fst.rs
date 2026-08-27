//! The title File System Table (`00000000.app`, content index 0).
//!
//! The FST maps every file in the title (its `code/`, `content/`, `meta/` trees) to the
//! content ("cluster") that stores it, plus the file's offset and size within that content.
//! The console reads it to locate files across the installed contents.
//!
//! Binary layout (big-endian), verified byte-for-byte against a retail title's FST:
//!
//! ```text
//! 0x00  "FST\0"
//! 0x04  u32 offset_factor         (file offsets are stored divided by this; 0x20)
//! 0x08  u32 secondary_header_count (== number of contents)
//! 0x0C  20 zero bytes
//! 0x20  secondary headers, 0x20 bytes each:
//!         u32 offset_sectors, u32 size_sectors, u64 owner_title_id,
//!         u32 group_id, u16 flags, 10 zero bytes
//!       then file/dir entries, 0x10 bytes each (root first):
//!         u8 type (bit0=dir, bit7=absent), u24 name_offset,
//!         u32 offset (file: byte offset/factor; dir: parent entry index),
//!         u32 size   (file: byte size; dir: index one past its last descendant),
//!         u16 flags, u16 storage_cluster_index
//!       then the name table: NUL-terminated names in entry order.
//! ```

use byteorder::{BigEndian, WriteBytesExt};
use std::io::Write;

/// Offset factor used for file offsets within contents (matches retail titles).
pub const OFFSET_FACTOR: u32 = 0x20;

/// A content descriptor ("secondary header" / cluster) in the FST.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FstContent {
    /// Content data offset, in 0x8000 sectors, cumulative across contents.
    pub offset_sectors: u32,
    /// Content data size, in 0x8000 sectors.
    pub size_sectors: u32,
    /// Owning title id (0 for shared/system contents).
    pub owner_title_id: u64,
    /// Group id (0, 0x400 for meta, or the title group for game content).
    pub group_id: u32,
    /// Cluster flags (0x0100 for non-hashed, 0x0200 for hashed contents).
    pub flags: u16,
}

/// A node in the title file tree.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum FstNodeKind {
    /// A file: raw byte offset within its content, and byte size.
    File { offset: u64, size: u64 },
    /// A directory: parent entry index, and the index one past its last descendant.
    Dir { parent_index: u32, end_index: u32 },
}

/// A file/directory entry.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FstNode {
    /// Entry name (empty for the root).
    pub name: String,
    /// File or directory payload.
    pub kind: FstNodeKind,
    /// Extra type-byte bits beyond the directory bit (bit0). Retail titles set 0x02 on the
    /// large game-data files that occupy a hashed content of their own (the `hif_*.nfs`).
    pub type_flags: u8,
    /// Entry flags (0x0000 code, 0x0040 meta, 0x0400 content).
    pub flags: u16,
    /// Index into the content table storing this entry.
    pub cluster: u16,
}

/// A complete FST ready to serialize.
#[derive(Clone, Debug)]
pub struct Fst {
    /// Offset factor (usually [`OFFSET_FACTOR`]).
    pub offset_factor: u32,
    /// The content/cluster descriptors.
    pub contents: Vec<FstContent>,
    /// The file/directory entries, root first, in depth-first order.
    pub nodes: Vec<FstNode>,
}

impl Fst {
    /// Serialize the FST to its on-disk byte form.
    pub fn serialize(&self) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(b"FST\0");
        out.write_u32::<BigEndian>(self.offset_factor).unwrap();
        out.write_u32::<BigEndian>(self.contents.len() as u32)
            .unwrap();
        // 0x0C..0x20 is zero in retail FSTs (the wiki's "0x0100" here does not match).
        out.extend_from_slice(&[0u8; 20]);

        for c in &self.contents {
            out.write_u32::<BigEndian>(c.offset_sectors).unwrap();
            out.write_u32::<BigEndian>(c.size_sectors).unwrap();
            out.write_u64::<BigEndian>(c.owner_title_id).unwrap();
            out.write_u32::<BigEndian>(c.group_id).unwrap();
            out.write_u16::<BigEndian>(c.flags).unwrap();
            out.extend_from_slice(&[0u8; 10]);
        }

        // Build the name table and record each node's name offset.
        let mut names = Vec::new();
        let mut name_offsets = Vec::with_capacity(self.nodes.len());
        for node in &self.nodes {
            name_offsets.push(names.len() as u32);
            names.extend_from_slice(node.name.as_bytes());
            names.push(0);
        }

        for (node, &name_off) in self.nodes.iter().zip(&name_offsets) {
            let (dir_bit, offset, size) = match node.kind {
                FstNodeKind::File { offset, size } => (
                    0x00u8,
                    (offset / self.offset_factor as u64) as u32,
                    size as u32,
                ),
                FstNodeKind::Dir {
                    parent_index,
                    end_index,
                } => (0x01u8, parent_index, end_index),
            };
            out.write_u8(dir_bit | node.type_flags).unwrap();
            out.write_u8((name_off >> 16) as u8).unwrap();
            out.write_u16::<BigEndian>((name_off & 0xFFFF) as u16)
                .unwrap();
            out.write_u32::<BigEndian>(offset).unwrap();
            out.write_u32::<BigEndian>(size).unwrap();
            out.write_u16::<BigEndian>(node.flags).unwrap();
            out.write_u16::<BigEndian>(node.cluster).unwrap();
        }

        out.write_all(&names).unwrap();
        out
    }

    /// Parse an FST from bytes (inverse of [`serialize`](Self::serialize)); trailing content
    /// padding after the name table is ignored.
    ///
    /// `data` may be untrusted (a downloaded/user-supplied title's content 0): every offset and
    /// count read from it is checked against `data`'s actual length before being used to index,
    /// so hostile values return `None` instead of panicking.
    pub fn parse(data: &[u8]) -> Option<Fst> {
        use byteorder::ByteOrder;
        if data.len() < 0x20 || &data[0..4] != b"FST\0" {
            return None;
        }
        let offset_factor = BigEndian::read_u32(&data[4..8]);
        let content_count = BigEndian::read_u32(&data[8..12]) as usize;

        // Bound the content table against `data`'s real length before trusting `content_count`
        // enough to index with it or size a `Vec::with_capacity`.
        let contents_bytes = content_count.checked_mul(0x20)?;
        let entries_start = 0x20usize.checked_add(contents_bytes)?;
        if data.len() < entries_start {
            return None;
        }

        let mut contents = Vec::with_capacity(content_count);
        for i in 0..content_count {
            let o = 0x20 + i * 0x20;
            contents.push(FstContent {
                offset_sectors: BigEndian::read_u32(&data[o..o + 4]),
                size_sectors: BigEndian::read_u32(&data[o + 4..o + 8]),
                owner_title_id: BigEndian::read_u64(&data[o + 8..o + 16]),
                group_id: BigEndian::read_u32(&data[o + 16..o + 20]),
                flags: BigEndian::read_u16(&data[o + 20..o + 22]),
            });
        }

        // The root entry's size field (at entries_start + 8..12) is the total number of entries;
        // make sure the root entry itself (0x10 bytes) is actually present before reading it.
        if data.len() < entries_start.checked_add(0x10)? {
            return None;
        }
        let root_size = BigEndian::read_u32(&data[entries_start + 8..entries_start + 12]) as usize;

        // Bound the entry table (and therefore the name table start) the same way.
        let entries_bytes = root_size.checked_mul(0x10)?;
        let name_table = entries_start.checked_add(entries_bytes)?;
        if data.len() < name_table {
            return None;
        }

        let read_name = |name_off: u32| -> Option<String> {
            let start = name_table.checked_add(name_off as usize)?;
            if start > data.len() {
                return None;
            }
            let end = data[start..]
                .iter()
                .position(|&b| b == 0)
                .map_or(data.len(), |p| start + p);
            Some(String::from_utf8_lossy(&data[start..end]).into_owned())
        };

        let mut nodes = Vec::with_capacity(root_size);
        for i in 0..root_size {
            // Safe: o + 0x10 <= entries_start + entries_bytes == name_table <= data.len(),
            // established above.
            let o = entries_start + i * 0x10;
            let type_byte = data[o];
            let name_off =
                ((data[o + 1] as u32) << 16) | BigEndian::read_u16(&data[o + 2..o + 4]) as u32;
            let offset = BigEndian::read_u32(&data[o + 4..o + 8]);
            let size = BigEndian::read_u32(&data[o + 8..o + 12]);
            let flags = BigEndian::read_u16(&data[o + 12..o + 14]);
            let cluster = BigEndian::read_u16(&data[o + 14..o + 16]);
            let kind = if type_byte & 0x01 != 0 {
                FstNodeKind::Dir {
                    parent_index: offset,
                    end_index: size,
                }
            } else {
                FstNodeKind::File {
                    offset: offset as u64 * offset_factor as u64,
                    size: size as u64,
                }
            };
            let type_flags = type_byte & !0x01;
            nodes.push(FstNode {
                name: read_name(name_off)?,
                kind,
                type_flags,
                flags,
                cluster,
            });
        }

        Some(Fst {
            offset_factor,
            contents,
            nodes,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn reference_fst_path() -> std::path::PathBuf {
        std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../.dev/wup_ref/fst_decrypted.bin")
    }

    #[test]
    fn round_trips_a_small_fst() {
        let fst = Fst {
            offset_factor: OFFSET_FACTOR,
            contents: vec![
                FstContent {
                    offset_sectors: 0,
                    size_sectors: 0,
                    owner_title_id: 0,
                    group_id: 0,
                    flags: 0x0100,
                },
                FstContent {
                    offset_sectors: 2,
                    size_sectors: 1,
                    owner_title_id: 0,
                    group_id: 0x400,
                    flags: 0x0200,
                },
            ],
            nodes: vec![
                FstNode {
                    name: String::new(),
                    kind: FstNodeKind::Dir {
                        parent_index: 0,
                        end_index: 3,
                    },
                    type_flags: 0,
                    flags: 0,
                    cluster: 0,
                },
                FstNode {
                    name: "meta".into(),
                    kind: FstNodeKind::Dir {
                        parent_index: 0,
                        end_index: 3,
                    },
                    type_flags: 0,
                    flags: 0x0040,
                    cluster: 1,
                },
                FstNode {
                    name: "meta.xml".into(),
                    kind: FstNodeKind::File {
                        offset: 0,
                        size: 9518,
                    },
                    type_flags: 0,
                    flags: 0x0040,
                    cluster: 1,
                },
            ],
        };
        let bytes = fst.serialize();
        let parsed = Fst::parse(&bytes).unwrap();
        assert_eq!(parsed.serialize(), bytes);
        assert_eq!(parsed.nodes[2].name, "meta.xml");
    }

    /// Parse a retail title's decrypted FST and confirm our serializer reproduces it exactly
    /// (up to the trailing content padding). This is the definitive format check.
    #[test]
    fn reproduces_reference_fst_byte_for_byte() {
        let path = reference_fst_path();
        if !path.exists() {
            eprintln!(
                "skipping reproduces_reference_fst_byte_for_byte: {} not present",
                path.display()
            );
            return;
        }
        let data = std::fs::read(&path).unwrap();
        let fst = Fst::parse(&data).expect("parse reference FST");
        let ours = fst.serialize();
        assert_eq!(fst.offset_factor, OFFSET_FACTOR);
        assert_eq!(fst.contents.len(), 19);
        assert_eq!(fst.nodes.len(), 47);
        // Everything up to our serialized length must match the reference bytes exactly.
        if let Some(i) = (0..ours.len()).find(|&i| data[i] != ours[i]) {
            let s = i.saturating_sub(4);
            panic!(
                "first diff at 0x{i:x}: ref={:02x?} ours={:02x?}",
                &data[s..(s + 16).min(data.len())],
                &ours[s..(s + 16).min(ours.len())]
            );
        }
        assert_eq!(
            &data[..ours.len()],
            ours.as_slice(),
            "serialized FST differs from reference"
        );
        // The remainder of the reference is zero padding to the content size.
        assert!(
            data[ours.len()..].iter().all(|&b| b == 0),
            "trailing bytes should be padding"
        );
    }

    // --- Hostile-input bounds checks ---------------------------------------------------
    // `Fst::parse` reads content_count / root_size / name offsets from untrusted bytes (a
    // downloaded or user-supplied title's content 0) and must return `None`, never panic, when
    // those values don't fit the actual buffer.

    /// A bare 0x20-byte FST header claiming `content_count` content descriptors.
    fn fst_header(content_count: u32) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(b"FST\0");
        out.extend_from_slice(&OFFSET_FACTOR.to_be_bytes());
        out.extend_from_slice(&content_count.to_be_bytes());
        out.extend_from_slice(&[0u8; 20]);
        out
    }

    #[test]
    fn parse_rejects_oversized_content_count() {
        // content_count claims far more content descriptors than the buffer could ever hold.
        let data = fst_header(u32::MAX);
        assert!(Fst::parse(&data).is_none());
    }

    #[test]
    fn parse_rejects_truncated_content_table() {
        // content_count = 1, but the buffer ends right after the header (no content bytes).
        let data = fst_header(1);
        assert!(Fst::parse(&data).is_none());
    }

    #[test]
    fn parse_rejects_root_size_past_buffer() {
        // content_count = 0, so entries start right after the 0x20-byte header. The root entry's
        // size field (the total entry count) claims far more entries than the buffer holds.
        let mut data = fst_header(0);
        data.extend_from_slice(&[0u8; 8]); // type byte + name_off + offset/parent_index
        data.extend_from_slice(&0x7FFF_FFFFu32.to_be_bytes()); // size = huge entry count
        data.extend_from_slice(&[0u8; 4]); // flags + cluster
        assert_eq!(data.len(), 0x30);
        assert!(Fst::parse(&data).is_none());
    }

    #[test]
    fn parse_rejects_name_offset_past_buffer() {
        // content_count = 0, root_size = 1 (just the root entry), but its name offset points
        // far past the end of the (short) name table.
        let mut data = fst_header(0);
        data.push(0x01); // dir bit
        data.extend_from_slice(&[0xFF, 0xFF, 0xFF]); // name_off = 0x00FFFFFF
        data.extend_from_slice(&0u32.to_be_bytes()); // parent_index
        data.extend_from_slice(&1u32.to_be_bytes()); // end_index / root entry count = 1
        data.extend_from_slice(&[0u8; 4]); // flags + cluster
        assert_eq!(data.len(), 0x30);
        assert!(Fst::parse(&data).is_none());
    }
}
