//! wiivci-core: library for injecting Wii games into Wii U Virtual Console (WUP) packages.
//!
//! The pipeline reads a Wii disc image (ISO/RVZ/… via [`nod`]), converts the decrypted
//! disc into the Wii U VC NFS format, merges it with a user-supplied base title, and
//! packages everything into an installable WUP package (title.tmd/tik/cert + .app/.h3).
//!
//! No decryption keys or Nintendo binaries are bundled: the Wii common key, the Wii U
//! common key, and the base title are all supplied by the user at runtime.

pub mod assets;
pub mod base;
pub mod error;
pub mod input;
pub mod keys;
pub mod meta;
pub mod nfs;
pub mod nus;
pub mod package;
pub mod pipeline;

pub use error::{Error, Result};
