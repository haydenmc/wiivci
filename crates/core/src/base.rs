//! The user-supplied Wii U base title.
//!
//! Every Wii VC injection is built on top of a real Wii U Virtual Console title (by
//! convention Rhythm Heaven Fever, `00050000101B0700`). The base supplies the closed
//! Nintendo framework binaries — `fw.img`, `frisbiiU.rpx`, `cos.xml`, `htk.bin`,
//! `nn_hai_user.rpl` — that have no clean-room reimplementation and cannot be redistributed.
//! The user obtains their own dump; this module never bundles one.
//!
//! Two [`BaseSource`] implementations are provided:
//!
//! * [`WuaBase`] — a Cemu `.wua` ZArchive (read natively via the pure-Rust `zarust` crate);
//! * [`DirBase`] — an already-extracted directory tree.
//!
//! Both [`stage`](BaseSource::stage) the base's `code/`, `content/` (minus the base's own
//! `hif_*.nfs`, which the injected game replaces) and `meta/` into a build directory, and
//! return the 16-byte `htk.bin` NFS key. The `NusBase` (download-from-NUS) implementation is
//! a planned future addition behind this same trait.

use std::fs;
use std::path::{Path, PathBuf};

use zarust::{ArchiveReader, EntryKind, NodeHandle, ROOT_NODE};

use crate::error::{Error, Result};

/// Files that must be present in a base title's `code/` directory.
pub const REQUIRED_CODE_FILES: &[&str] =
    &["cos.xml", "frisbiiU.rpx", "fw.img", "fw.tmd", "htk.bin", "nn_hai_user.rpl"];

/// A base title staged into a build directory.
pub struct StagedBase {
    /// The 16-byte NFS AES key read from `code/htk.bin`.
    pub htk: [u8; 16],
    /// Path to the staged `code/` directory.
    pub code_dir: PathBuf,
    /// Path to the staged `content/` directory.
    pub content_dir: PathBuf,
    /// Path to the staged `meta/` directory.
    pub meta_dir: PathBuf,
}

/// A provider of Wii U base-title content.
pub trait BaseSource {
    /// Stage the base's `code/`, `content/` and `meta/` trees into `build_dir`, skipping the
    /// base's own `hif_*.nfs` game data. `build_dir` must already exist.
    fn stage(&mut self, build_dir: &Path) -> Result<StagedBase>;
}

fn is_base_game_nfs(name: &str) -> bool {
    name.starts_with("hif_") && name.ends_with(".nfs")
}

fn finalize_stage(build_dir: &Path) -> Result<StagedBase> {
    let code_dir = build_dir.join("code");
    let content_dir = build_dir.join("content");
    let meta_dir = build_dir.join("meta");

    for f in REQUIRED_CODE_FILES {
        let p = code_dir.join(f);
        if !p.exists() {
            return Err(Error::MissingFile(p));
        }
    }
    let htk_path = code_dir.join("htk.bin");
    let htk_bytes = fs::read(&htk_path).map_err(|e| Error::io(&htk_path, e))?;
    let htk: [u8; 16] = htk_bytes.as_slice().try_into().map_err(|_| Error::InvalidKey {
        name: "htk.bin",
        reason: format!("expected 16 bytes, got {}", htk_bytes.len()),
    })?;

    Ok(StagedBase { htk, code_dir, content_dir, meta_dir })
}

// ---------------------------------------------------------------------------
// .wua (ZArchive) base
// ---------------------------------------------------------------------------

/// A base title read from a Cemu `.wua` ZArchive.
pub struct WuaBase {
    reader: ArchiveReader<fs::File>,
    /// Handle of the `<titleId>_v<version>` title root inside the archive.
    title_root: NodeHandle,
}

impl WuaBase {
    /// Open a `.wua` archive and locate its title root.
    ///
    /// If the archive holds multiple titles, the first one containing a `code/` directory is
    /// used.
    pub fn open(path: impl AsRef<Path>) -> Result<Self> {
        let path = path.as_ref();
        let reader = ArchiveReader::open(path).map_err(|e| wua_err(path, e))?;

        let mut title_root = None;
        for entry in reader.directory_entries(ROOT_NODE).map_err(|e| wua_err(path, e))? {
            if entry.kind == EntryKind::Directory {
                // A title root has a `code/` child.
                if let Ok(children) = reader.directory_entries(entry.handle) {
                    if children.iter().any(|c| c.name == b"code" && c.is_directory()) {
                        title_root = Some(entry.handle);
                        break;
                    }
                }
            }
        }
        let title_root = title_root.ok_or_else(|| {
            Error::UnsupportedDisc(format!(
                "no Wii U title (a '<id>_v<n>/code/' tree) found in {}",
                path.display()
            ))
        })?;

        Ok(WuaBase { reader, title_root })
    }

    fn copy_dir(&mut self, handle: NodeHandle, dest: &Path) -> Result<()> {
        fs::create_dir_all(dest).map_err(|e| Error::io(dest, e))?;
        // Collect owned entries first so the immutable borrow ends before read_file_to_end.
        let entries: Vec<(String, EntryKind, NodeHandle)> = self
            .reader
            .directory_entries(handle)
            .map_err(|e| Error::Other(anyhow::anyhow!(e)))?
            .into_iter()
            .map(|e| (String::from_utf8_lossy(e.name).into_owned(), e.kind, e.handle))
            .collect();

        for (name, kind, h) in entries {
            let path = dest.join(&name);
            match kind {
                EntryKind::Directory => self.copy_dir(h, &path)?,
                EntryKind::File => {
                    if is_base_game_nfs(&name) {
                        continue;
                    }
                    let data = self
                        .reader
                        .read_file_to_end(h)
                        .map_err(|e| Error::Other(anyhow::anyhow!(e)))?;
                    fs::write(&path, data).map_err(|e| Error::io(&path, e))?;
                }
            }
        }
        Ok(())
    }
}

impl BaseSource for WuaBase {
    fn stage(&mut self, build_dir: &Path) -> Result<StagedBase> {
        let title_root = self.title_root;
        // Copy code/, content/ (minus hif_*.nfs), meta/.
        let subdirs: Vec<(String, NodeHandle)> = self
            .reader
            .directory_entries(title_root)
            .map_err(|e| Error::Other(anyhow::anyhow!(e)))?
            .into_iter()
            .filter(|e| e.is_directory())
            .map(|e| (String::from_utf8_lossy(e.name).into_owned(), e.handle))
            .collect();

        for (name, handle) in subdirs {
            self.copy_dir(handle, &build_dir.join(&name))?;
        }
        finalize_stage(build_dir)
    }
}

fn wua_err(path: &Path, e: zarust::Error) -> Error {
    Error::Other(anyhow::anyhow!("reading {}: {}", path.display(), e))
}

// ---------------------------------------------------------------------------
// Extracted-directory base
// ---------------------------------------------------------------------------

/// A base title read from an already-extracted directory tree.
pub struct DirBase {
    root: PathBuf,
}

impl DirBase {
    /// Point at a directory containing `code/`, `content/`, `meta/` — either directly or one
    /// level down inside a single `<titleId>_v<n>` subfolder (as produced by extracting a
    /// `.wua`).
    pub fn new(path: impl AsRef<Path>) -> Result<Self> {
        let path = path.as_ref();
        if path.join("code").is_dir() {
            return Ok(DirBase { root: path.to_path_buf() });
        }
        // Look one level down for a title folder.
        if let Ok(read) = fs::read_dir(path) {
            for entry in read.flatten() {
                let p = entry.path();
                if p.is_dir() && p.join("code").is_dir() {
                    return Ok(DirBase { root: p });
                }
            }
        }
        Err(Error::UnsupportedDisc(format!(
            "no 'code/' directory found in base path {}",
            path.display()
        )))
    }
}

impl BaseSource for DirBase {
    fn stage(&mut self, build_dir: &Path) -> Result<StagedBase> {
        for sub in ["code", "content", "meta"] {
            let src = self.root.join(sub);
            if src.is_dir() {
                copy_tree(&src, &build_dir.join(sub))?;
            }
        }
        finalize_stage(build_dir)
    }
}

/// Recursively copy `src` into `dest`, skipping the base's own `hif_*.nfs` files.
fn copy_tree(src: &Path, dest: &Path) -> Result<()> {
    fs::create_dir_all(dest).map_err(|e| Error::io(dest, e))?;
    for entry in fs::read_dir(src).map_err(|e| Error::io(src, e))? {
        let entry = entry.map_err(|e| Error::io(src, e))?;
        let name = entry.file_name();
        let from = entry.path();
        let to = dest.join(&name);
        if from.is_dir() {
            copy_tree(&from, &to)?;
        } else if !is_base_game_nfs(&name.to_string_lossy()) {
            fs::copy(&from, &to).map_err(|e| Error::io(&from, e))?;
        }
    }
    Ok(())
}

/// Open a base title from a path, dispatching on extension (`.wua` vs directory).
pub fn open_base(path: impl AsRef<Path>) -> Result<Box<dyn BaseSource>> {
    let path = path.as_ref();
    if path.is_dir() {
        Ok(Box::new(DirBase::new(path)?))
    } else if path.extension().is_some_and(|e| e.eq_ignore_ascii_case("wua")) {
        Ok(Box::new(WuaBase::open(path)?))
    } else {
        Err(Error::UnsupportedDisc(format!(
            "base must be a directory or a .wua archive: {}",
            path.display()
        )))
    }
}
