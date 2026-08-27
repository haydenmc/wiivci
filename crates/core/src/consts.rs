//! Numeric constants for the Wii partition / hash-tree layout, shared by [`crate::disc_patch`],
//! [`crate::nfs`], [`crate::wii_author`], [`crate::input`] and the TMD/ticket fakesign patching
//! in [`crate::pipeline`].
//!
//! Before this module existed, each value below was independently declared (under a few
//! different names) in two to four of those files. Consolidating them here is a pure
//! deduplication — every value is unchanged from before.

/// Clusters per Wii hash group: 64 clusters share one `H3` table entry.
pub(crate) const SECTORS_PER_GROUP: usize = 64;

/// Size of a cluster's hash block (the `H0`/`H1`/`H2` sub-tables) at the start of every 0x8000
/// cluster.
pub(crate) const HASH_BLOCK: usize = 0x400;

/// Bytes of real (non-hash) data per cluster: the 0x8000 cluster minus its [`HASH_BLOCK`].
pub(crate) const CLUSTER_DATA: usize = crate::input::DISC_SECTOR_SIZE - HASH_BLOCK; // 0x7C00

/// Offset of the Wii TMD's single content-record hash (a 20-byte SHA-1) within the TMD.
pub(crate) const TMD_CONTENT0_HASH: usize = 0x1F4;

/// The RSA-2048 signature region of a Wii ticket/TMD (`0x004..0x104`), zeroed to fakesign it.
pub(crate) const WII_SIG: std::ops::Range<usize> = 0x004..0x104;
