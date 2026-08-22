//! Reading the source Wii disc image via the [`nod`] crate.
//!
//! `nod` transparently handles ISO / RVZ / WBFS / CISO / NKit / GCZ inputs and performs Wii
//! partition AES decryption internally. We open the disc in **decrypted mode**
//! (`rebuild_encryption: false`) so that reading the disc stream yields the logical disc
//! image with partition data already decrypted *and hash blocks intact* — precisely the
//! representation the Wii U VC NFS format stores.
//!
//! The Wii common key is read by `nod` from its own key store; callers must ensure it is
//! available (see [`crate::keys`]). We additionally extract the game partition's `ticket.bin`
//! and `tmd.bin`, which become `code/rvlt.tik` / `code/rvlt.tmd` in the output package.

use std::path::{Path, PathBuf};

use nod::{Disc, OpenOptions, PartitionKind, SECTOR_SIZE};

use crate::error::{Error, Result};

/// Size of a Wii/GC disc sector: 0x8000 bytes. Re-exported from `nod` for convenience.
pub const DISC_SECTOR_SIZE: usize = SECTOR_SIZE;

/// A source Wii disc opened for reading in decrypted mode.
pub struct SourceDisc {
    disc: Disc,
    path: PathBuf,
    game_id: [u8; 6],
    disc_size: u64,
    /// The data partition's sector span (start of partition .. end of partition data).
    data_partition: PartitionSpan,
    /// Every partition's sector span, sorted ascending by start sector.
    partitions: Vec<PartitionSpan>,
    raw_ticket: Vec<u8>,
    raw_tmd: Vec<u8>,
    raw_cert_chain: Option<Vec<u8>>,
}

/// The sector range occupied by a partition on the logical disc.
#[derive(Clone, Copy, Debug)]
pub struct PartitionSpan {
    /// First sector of the partition (its header/ticket/tmd).
    pub start_sector: u32,
    /// First sector of the (now-decrypted) partition data.
    pub data_start_sector: u32,
    /// One past the last sector of the partition data.
    pub data_end_sector: u32,
}

impl SourceDisc {
    /// Open a Wii disc image in decrypted mode.
    pub fn open(path: impl AsRef<Path>) -> Result<Self> {
        let path = path.as_ref().to_path_buf();
        let options = OpenOptions { rebuild_encryption: false, ..Default::default() };
        let disc = Disc::new_with_options(&path, &options)?;

        let header = disc.header();
        if !header.is_wii() {
            return Err(Error::UnsupportedDisc(format!(
                "'{}' is not a Wii disc (GameCube and other platforms are not yet supported)",
                path.display()
            )));
        }
        let mut game_id = [0u8; 6];
        game_id.copy_from_slice(&header.game_id);
        let disc_size = disc.disc_size();

        // Collect every partition span; identify the data (game) partition.
        let span_of = |p: &nod::PartitionInfo| PartitionSpan {
            start_sector: p.start_sector,
            data_start_sector: p.data_start_sector,
            data_end_sector: p.data_end_sector,
        };
        let mut partitions: Vec<PartitionSpan> = disc.partitions().iter().map(span_of).collect();
        partitions.sort_by_key(|p| p.start_sector);
        let data_partition = disc
            .partitions()
            .iter()
            .find(|p| p.kind == PartitionKind::Data)
            .map(span_of)
            .ok_or_else(|| Error::UnsupportedDisc("no data partition found on disc".into()))?;

        // Extract the game partition's ticket / tmd / cert chain for rvlt.* files.
        let mut partition = disc.open_partition_kind(PartitionKind::Data)?;
        let meta = partition.meta()?;
        let raw_ticket = meta
            .raw_ticket
            .as_ref()
            .ok_or_else(|| Error::UnsupportedDisc("partition has no ticket".into()))?
            .to_vec();
        let raw_tmd = meta
            .raw_tmd
            .as_ref()
            .ok_or_else(|| Error::UnsupportedDisc("partition has no TMD".into()))?
            .to_vec();
        let raw_cert_chain = meta.raw_cert_chain.as_ref().map(|v| v.to_vec());

        Ok(SourceDisc {
            disc,
            path,
            game_id,
            disc_size,
            data_partition,
            partitions,
            raw_ticket,
            raw_tmd,
            raw_cert_chain,
        })
    }

    /// The 6-character game ID (e.g. `RSPE01`).
    pub fn game_id(&self) -> [u8; 6] { self.game_id }

    /// The 6-character game ID as a string.
    pub fn game_id_str(&self) -> String { String::from_utf8_lossy(&self.game_id).into_owned() }

    /// The 4-character disc ID used to derive the Wii U title ID (first 4 game-id bytes).
    pub fn disc_id4(&self) -> [u8; 4] {
        [self.game_id[0], self.game_id[1], self.game_id[2], self.game_id[3]]
    }

    /// The logical disc size in bytes.
    pub fn disc_size(&self) -> u64 { self.disc_size }

    /// The data partition's sector span.
    pub fn data_partition(&self) -> PartitionSpan { self.data_partition }

    /// Every partition's sector span, sorted ascending by start sector.
    pub fn partitions(&self) -> &[PartitionSpan] { &self.partitions }

    /// The game partition ticket bytes (`code/rvlt.tik`).
    pub fn raw_ticket(&self) -> &[u8] { &self.raw_ticket }

    /// The game partition TMD bytes (`code/rvlt.tmd`).
    pub fn raw_tmd(&self) -> &[u8] { &self.raw_tmd }

    /// The game partition certificate chain, if present.
    pub fn raw_cert_chain(&self) -> Option<&[u8]> { self.raw_cert_chain.as_deref() }

    /// The path the disc was opened from.
    pub fn path(&self) -> &Path { &self.path }

    /// Mutable access to the underlying decrypted disc stream (`Read + Seek`).
    ///
    /// Reading yields the full logical disc image with partition data decrypted and hash
    /// blocks intact; sectors outside partitions are raw disc bytes.
    pub fn stream(&mut self) -> &mut Disc { &mut self.disc }
}
