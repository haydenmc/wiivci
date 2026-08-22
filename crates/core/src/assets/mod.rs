//! Boot-texture conversion and best-effort artwork/title fetching for injected titles.

pub mod artrepo;
pub mod gametdb;
pub mod images;

pub use artrepo::{art_png_name, download_texture};
pub use gametdb::lookup_title;
pub use images::{png_to_tga, BootTexture};
