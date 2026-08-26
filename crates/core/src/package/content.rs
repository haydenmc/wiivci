//! Assigning the staged `code/`, `content/`, `meta/` files to contents and building the FST.
//!
//! The layout mirrors a working retail/TeconMoon inject byte-for-byte in structure (confirmed
//! necessary: the Wii U installer hangs on other content layouts — see the install-hang saga). The
//! content order and grouping are:
//!
//! 1. content 0 = FST;
//! 2. `code/app.xml`, then `code/cos.xml` — each its own non-hashed content;
//! 3. `meta/` split into hashed contents: `meta.xml` alone, the boot bundle
//!    ([`META_BOOT_BUNDLE`]) together, [`META_SINGLES`] each alone, then any leftover meta files
//!    grouped into one;
//! 4. the remaining `code/` files (`.rpx`/`.rpl` first) — each its own non-hashed content;
//! 5. `content/` (game data: shaders + `hif_*.nfs`) — title-owned hashed content(s) of up to
//!    [`MAX_GAME_CONTENT_BYTES`], placed **LAST** (no content may follow the game data).

use std::collections::HashMap;
use std::path::{Path, PathBuf};

use crate::error::{Error, Result};

use super::fst::{Fst, FstContent, FstNode, FstNodeKind, OFFSET_FACTOR};

/// TMD/FST content type for non-hashed content.
pub const TYPE_NONHASHED: u16 = 0x2001;
/// TMD/FST content type for hashed content.
pub const TYPE_HASHED: u16 = 0x2003;

const SECTOR: u64 = 0x8000;

/// A file placed within a content, at a byte offset relative to the content start.
#[derive(Clone, Debug)]
pub struct PlacedFile {
    /// Absolute path on disk.
    pub path: PathBuf,
    /// Byte offset within the content (0x20-aligned).
    pub offset: u64,
    /// File size in bytes.
    pub size: u64,
}

/// A planned content to be encrypted and written.
#[derive(Clone, Debug)]
pub struct PlannedContent {
    /// Content index / id.
    pub index: u16,
    /// Content type (`TYPE_HASHED` / `TYPE_NONHASHED`).
    pub content_type: u16,
    /// Files in this content, in placement order (empty for the FST content).
    pub files: Vec<PlacedFile>,
    /// Total decrypted size of the content's data (before encryption padding).
    pub data_len: u64,
    /// True for the game (`hif_*.nfs`) contents. These must carry a non-zero owner title id and a
    /// game-specific group id in the FST content table, or the Wii U installer hangs when it
    /// finalises the content. Metadata/code contents keep owner 0 (matching retail).
    pub is_game: bool,
}

/// The full package plan: the serialized FST (content 0) and every content's file layout.
pub struct PackagePlan {
    /// Serialized FST bytes (the data for content 0).
    pub fst: Vec<u8>,
    /// All contents, index 0 first (the FST content).
    pub contents: Vec<PlannedContent>,
}

// Intermediate tree node before FST serialization.
enum Tree {
    Dir {
        name: String,
        flags: u16,
        children: Vec<Tree>,
    },
    File {
        name: String,
        path: PathBuf,
        size: u64,
        cluster: u16,
        flags: u16,
        type_flags: u8,
    },
}

fn align_up(n: u64, to: u64) -> u64 {
    n.div_ceil(to) * to
}

fn is_hif(name: &str) -> bool {
    name.starts_with("hif_") && name.ends_with(".nfs")
}

/// Maximum decrypted bytes packed into a single game content before rolling over to a new one.
/// The reference packers (NUSPacker/UWUVCI) group game data into large contents rather than one
/// content per file; the Wii U installer hangs installing a package that splits the game across
/// many small contents (confirmed: the same game data installs as one content but hangs when split
/// per-`hif`).
///
/// The cap must keep each encrypted `.app` (~1.6% larger than the decrypted data here) **under 2
/// GiB** (`INT32_MAX`): a content ≥2 GiB hangs the installer immediately (a size field is handled
/// as signed 32-bit somewhere in the install path — matching NUSPacker's historical 2 GiB limit,
/// and confirmed on hardware where 2.98 GiB game contents hung at install while ≤1.2 GiB ones
/// installed). 1.75 GiB decrypted → ~1.74 GiB `.app`, a comfortable margin. NOT a hash-group
/// boundary — game contents may hold many `hif_*.nfs` files.
const MAX_GAME_CONTENT_BYTES: u64 = 0x7000_0000; // 1.75 GiB (keeps the .app under 2 GiB)

/// Rolling state for packing `hif_*.nfs` game files into a few large contents.
struct GameGrouping {
    /// Index of the content currently being filled, if any.
    current: Option<u16>,
    /// Decrypted bytes already assigned to `current`.
    current_size: u64,
}

impl GameGrouping {
    fn new() -> Self {
        GameGrouping {
            current: None,
            current_size: 0,
        }
    }

    /// Return the content index a game file of `size` bytes should join, creating a new content
    /// when the current one is full (or none exists yet).
    fn content_for(&mut self, size: u64, contents: &mut Vec<PlannedContent>) -> u16 {
        let placed = align_up(size, OFFSET_FACTOR as u64);
        match self.current {
            Some(idx) if self.current_size + placed <= MAX_GAME_CONTENT_BYTES => {
                self.current_size += placed;
                idx
            }
            _ => {
                let idx = contents.len() as u16;
                contents.push(PlannedContent {
                    index: idx,
                    content_type: TYPE_HASHED,
                    files: Vec::new(),
                    data_len: 0,
                    is_game: true,
                });
                self.current = Some(idx);
                self.current_size = placed;
                idx
            }
        }
    }
}

fn read_dir_sorted(dir: &Path) -> Result<Vec<std::fs::DirEntry>> {
    let mut entries: Vec<_> = std::fs::read_dir(dir)
        .map_err(|e| Error::io(dir, e))?
        .collect::<std::result::Result<_, _>>()
        .map_err(|e| Error::io(dir, e))?;
    // Case-insensitive by name, matching retail FST ordering.
    entries.sort_by_key(|e| e.file_name().to_string_lossy().to_lowercase());
    Ok(entries)
}

/// Like [`read_dir_sorted`] but places `hif_*.nfs` files first. In the game (`content/`) directory
/// this puts `hif_000000.nfs` at offset 0 of the game content — `fw.img` reads the game content
/// from offset 0 as the NFS (its EGGS header must be there), so the disc data must precede the
/// shader assets, or the emulator hangs at boot. No effect on `code/`/`meta/` (no hif files).
fn read_dir_hif_first(dir: &Path) -> Result<Vec<std::fs::DirEntry>> {
    let mut entries = read_dir_sorted(dir)?;
    entries.sort_by_key(|e| {
        let n = e.file_name().to_string_lossy().to_lowercase();
        (!is_hif(&n), n) // hif files first, then everything else in name order
    });
    Ok(entries)
}

/// Meta files that share one hashed content in retail/TeconMoon layouts (the "boot bundle").
const META_BOOT_BUNDLE: &[&str] = &[
    "iconTex.tga",
    "bootTvTex.tga",
    "bootDrcTex.tga",
    "bootSound.btsnd",
];
/// Meta files that each get their own hashed content, in this order (after meta.xml and the bundle).
const META_SINGLES: &[&str] = &["bootMovie.h264", "bootLogoTex.tga"];

/// Plan the package layout from a staged build directory.
///
/// `title_id` is the Wii U title id; it derives the owner title id and group id stamped on the
/// game (`content/`) contents in the FST content table.
///
/// Content order mirrors a working retail/TeconMoon inject (confirmed necessary — the Wii U
/// installer hangs on other layouts): FST, `app.xml`, `cos.xml`, then the split `meta/` contents
/// (hashed), then the remaining `code/` files (non-hashed), then the `content/` game data (hashed,
/// title-owned) LAST.
pub fn plan(build_dir: &Path, title_id: u64) -> Result<PackagePlan> {
    let code_dir = build_dir.join("code");
    let content_dir = build_dir.join("content");
    let meta_dir = build_dir.join("meta");

    // Content 0 is the FST; the rest are allocated below in install order.
    let mut contents: Vec<PlannedContent> = vec![PlannedContent {
        index: 0,
        content_type: TYPE_NONHASHED,
        files: Vec::new(),
        data_len: 0,
        is_game: false,
    }];
    // Assigned content index per staged file path.
    let mut cluster_of: HashMap<PathBuf, u16> = HashMap::new();

    let alloc = |ct: u16, is_game: bool, contents: &mut Vec<PlannedContent>| -> u16 {
        let idx = contents.len() as u16;
        contents.push(PlannedContent {
            index: idx,
            content_type: ct,
            files: Vec::new(),
            data_len: 0,
            is_game,
        });
        idx
    };

    // 1. app.xml, then cos.xml — each its own non-hashed content.
    for name in ["app.xml", "cos.xml"] {
        let p = code_dir.join(name);
        if p.is_file() {
            let idx = alloc(TYPE_NONHASHED, false, &mut contents);
            cluster_of.insert(p, idx);
        }
    }

    // 2. meta/ — split into hashed contents: meta.xml alone, the boot bundle together, then the
    //    known singles, then any leftover meta files grouped into one content.
    if meta_dir.is_dir() {
        if meta_dir.join("meta.xml").is_file() {
            let idx = alloc(TYPE_HASHED, false, &mut contents);
            cluster_of.insert(meta_dir.join("meta.xml"), idx);
        }
        let bundle: Vec<&&str> = META_BOOT_BUNDLE
            .iter()
            .filter(|f| meta_dir.join(f).is_file())
            .collect();
        if !bundle.is_empty() {
            let idx = alloc(TYPE_HASHED, false, &mut contents);
            for f in bundle {
                cluster_of.insert(meta_dir.join(f), idx);
            }
        }
        for f in META_SINGLES {
            if meta_dir.join(f).is_file() {
                let idx = alloc(TYPE_HASHED, false, &mut contents);
                cluster_of.insert(meta_dir.join(f), idx);
            }
        }
        // Any other meta files (e.g. Manual.bfma, rating images the base retains but TeconMoon
        // strips) share ONE hashed content, matching retail (which groups them) — one-per-file
        // would explode the content count.
        let leftover: Vec<PathBuf> = read_dir_sorted(&meta_dir)?
            .into_iter()
            .map(|e| e.path())
            .filter(|p| p.is_file() && !cluster_of.contains_key(p))
            .collect();
        if !leftover.is_empty() {
            let idx = alloc(TYPE_HASHED, false, &mut contents);
            for p in leftover {
                cluster_of.insert(p, idx);
            }
        }
    }

    // 3. remaining code/ files (everything except app.xml/cos.xml) — each its own non-hashed
    //    content, .rpx/.rpl first (matching the reference layout), then the rest sorted.
    if code_dir.is_dir() {
        let mut rest: Vec<PathBuf> = read_dir_sorted(&code_dir)?
            .into_iter()
            .map(|e| e.path())
            .filter(|p| {
                p.is_file() && !cluster_of.contains_key(p) // app.xml/cos.xml already assigned
            })
            .collect();
        rest.sort_by_key(|p| {
            let n = p.file_name().unwrap().to_string_lossy().to_lowercase();
            let exec = n.ends_with(".rpx") || n.ends_with(".rpl");
            (!exec, n)
        });
        for p in rest {
            let idx = alloc(TYPE_NONHASHED, false, &mut contents);
            cluster_of.insert(p, idx);
        }
    }

    // 4. content/ (game data: shaders + hif) — title-owned hashed content(s), packed to
    //    MAX_GAME_CONTENT_BYTES, placed LAST.
    if content_dir.is_dir() {
        let mut game = GameGrouping::new();
        for (path, size) in collect_files(&content_dir)? {
            let idx = game.content_for(size, &mut contents);
            cluster_of.insert(path, idx);
        }
    }

    // Build the FST directory tree (code, content, meta) referencing the assigned clusters.
    let mut root_children = Vec::new();
    if code_dir.is_dir() {
        let children = build_dir_tree(&code_dir, 0x0000, 0x0000, &cluster_of)?;
        if !children.is_empty() {
            root_children.push(Tree::Dir {
                name: "code".into(),
                flags: 0x0000,
                children,
            });
        }
    }
    if content_dir.is_dir() {
        let children = build_dir_tree(&content_dir, 0x0400, 0x0400, &cluster_of)?;
        if !children.is_empty() {
            root_children.push(Tree::Dir {
                name: "content".into(),
                flags: 0x0400,
                children,
            });
        }
    }
    if meta_dir.is_dir() {
        let children = build_dir_tree(&meta_dir, 0x0040, 0x0040, &cluster_of)?;
        if !children.is_empty() {
            root_children.push(Tree::Dir {
                name: "meta".into(),
                flags: 0x0040,
                children,
            });
        }
    }

    // Flatten to FST nodes, assigning per-content offsets in traversal order.
    let mut nodes: Vec<FstNode> = Vec::new();
    // Root node placeholder; end_index filled after flattening.
    nodes.push(FstNode {
        name: String::new(),
        kind: FstNodeKind::Dir {
            parent_index: 0,
            end_index: 0,
        },
        type_flags: 0,
        flags: 0,
        cluster: 0,
    });
    flatten(&root_children, 0, &mut nodes, &mut contents);
    let total = nodes.len() as u32;
    if let FstNodeKind::Dir { end_index, .. } = &mut nodes[0].kind {
        *end_index = total;
    }

    // The game contents are owned by the vWii disc-title equivalent (0x00050000_<gameid>) and
    // carry a game-specific group id (low 16 bits of the title id), matching a working retail/
    // TeconMoon inject. Metadata/code contents keep owner 0. Getting this wrong makes the Wii U
    // installer hang when it finalises the first game content.
    let game_owner_title_id = 0x0005_0000_0000_0000 | (title_id & 0xFFFF_FFFF);
    let game_group_id = (title_id & 0xFFFF) as u32;

    // Compute FST secondary headers (cumulative content offsets in sectors).
    let mut fst_contents = Vec::with_capacity(contents.len());
    let mut cursor_sectors: u32 = 0;
    for c in &contents {
        let size_sectors = align_up(c.data_len.max(1), SECTOR) / SECTOR;
        let (owner_title_id, group_id, flags) = if c.is_game {
            (game_owner_title_id, game_group_id, 0x0200u16)
        } else {
            match c.content_type {
                TYPE_HASHED => (0, 0x0400u32, 0x0200u16),
                _ => (0, 0x0000, 0x0100),
            }
        };
        fst_contents.push(FstContent {
            offset_sectors: cursor_sectors,
            size_sectors: size_sectors as u32,
            owner_title_id,
            group_id,
            flags,
        });
        cursor_sectors += size_sectors as u32;
    }

    let fst = Fst {
        offset_factor: OFFSET_FACTOR,
        contents: fst_contents,
        nodes,
    };
    let fst_bytes = fst.serialize();
    // Record the FST content's own data length.
    contents[0].data_len = fst_bytes.len() as u64;

    Ok(PackagePlan {
        fst: fst_bytes,
        contents,
    })
}

/// Recursively collect all files under `dir` (depth-first, sorted) as (path, size), in FST order.
fn collect_files(dir: &Path) -> Result<Vec<(PathBuf, u64)>> {
    let mut out = Vec::new();
    for entry in read_dir_hif_first(dir)? {
        let path = entry.path();
        if path.is_dir() {
            out.extend(collect_files(&path)?);
        } else {
            let size = entry.metadata().map_err(|e| Error::io(&path, e))?.len();
            out.push((path, size));
        }
    }
    Ok(out)
}

/// Build the FST subtree for `dir`, taking each file's content index from `cluster_of` (assigned
/// during content allocation). `hif_*.nfs` files carry the 0x02 entry-type flag.
fn build_dir_tree(
    dir: &Path,
    dir_flags: u16,
    file_flags: u16,
    cluster_of: &HashMap<PathBuf, u16>,
) -> Result<Vec<Tree>> {
    let mut out = Vec::new();
    for entry in read_dir_hif_first(dir)? {
        let name = entry.file_name().to_string_lossy().into_owned();
        let path = entry.path();
        if path.is_dir() {
            let children = build_dir_tree(&path, dir_flags, file_flags, cluster_of)?;
            out.push(Tree::Dir {
                name,
                flags: dir_flags,
                children,
            });
        } else {
            let size = entry.metadata().map_err(|e| Error::io(&path, e))?.len();
            let cluster = *cluster_of.get(&path).ok_or_else(|| {
                Error::UnsupportedDisc(format!("{} was not assigned to a content", path.display()))
            })?;
            let type_flags = if is_hif(&name) { 0x02 } else { 0x00 };
            out.push(Tree::File {
                name,
                path,
                size,
                cluster,
                flags: file_flags,
                type_flags,
            });
        }
    }
    Ok(out)
}

fn flatten(
    children: &[Tree],
    parent_index: u32,
    nodes: &mut Vec<FstNode>,
    contents: &mut [PlannedContent],
) {
    for child in children {
        match child {
            Tree::Dir {
                name,
                flags,
                children,
            } => {
                let my_index = nodes.len() as u32;
                nodes.push(FstNode {
                    name: name.clone(),
                    kind: FstNodeKind::Dir {
                        parent_index,
                        end_index: 0,
                    },
                    type_flags: 0,
                    flags: *flags,
                    cluster: 0,
                });
                flatten(children, my_index, nodes, contents);
                let end = nodes.len() as u32;
                if let FstNodeKind::Dir { end_index, .. } = &mut nodes[my_index as usize].kind {
                    *end_index = end;
                }
                // A directory's cluster mirrors its first child's (cosmetic).
                let cluster = nodes
                    .get(my_index as usize + 1)
                    .map(|n| n.cluster)
                    .unwrap_or(0);
                nodes[my_index as usize].cluster = cluster;
            }
            Tree::File {
                name,
                path,
                size,
                cluster,
                flags,
                type_flags,
            } => {
                let c = &mut contents[*cluster as usize];
                let offset = align_up(c.data_len, OFFSET_FACTOR as u64);
                c.files.push(PlacedFile {
                    path: path.clone(),
                    offset,
                    size: *size,
                });
                c.data_len = offset + *size;
                nodes.push(FstNode {
                    name: name.clone(),
                    kind: FstNodeKind::File {
                        offset,
                        size: *size,
                    },
                    type_flags: *type_flags,
                    flags: *flags,
                    cluster: *cluster,
                });
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn plans_a_small_tree() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        std::fs::create_dir_all(root.join("code")).unwrap();
        std::fs::create_dir_all(root.join("content/assets/shaders/cafe")).unwrap();
        std::fs::create_dir_all(root.join("meta")).unwrap();
        std::fs::write(root.join("code/app.xml"), b"<app/>").unwrap();
        std::fs::write(root.join("code/cos.xml"), b"<cos/>").unwrap();
        std::fs::write(root.join("code/frisbiiU.rpx"), vec![0u8; 100]).unwrap();
        std::fs::write(
            root.join("content/assets/shaders/cafe/banner.gsh"),
            vec![1u8; 50],
        )
        .unwrap();
        std::fs::write(root.join("content/hif_000000.nfs"), vec![2u8; 0x8000]).unwrap();
        std::fs::write(root.join("meta/meta.xml"), b"<menu/>").unwrap();
        std::fs::write(root.join("meta/iconTex.tga"), vec![3u8; 200]).unwrap();

        let plan = plan(root, 0x00050002_534b4a45).unwrap();
        // FST content + code content + rpx content + assets content + hif content + meta content
        assert!(plan.contents.len() >= 6);
        assert!(!plan.fst.is_empty());

        // FST must round-trip and contain the expected files.
        let parsed = Fst::parse(&plan.fst).unwrap();
        let names: Vec<_> = parsed.nodes.iter().map(|n| n.name.as_str()).collect();
        assert!(names.contains(&"frisbiiU.rpx"));
        assert!(names.contains(&"hif_000000.nfs"));
        // The hif file carries the 0x02 entry type flag.
        let hif = parsed
            .nodes
            .iter()
            .find(|n| n.name == "hif_000000.nfs")
            .unwrap();
        assert_eq!(hif.type_flags, 0x02);
        // The game (hif) content is owned by the vWii disc title and has the game group id; a
        // zero owner makes the Wii U installer hang finalising it.
        let game_ct = &parsed.contents[hif.cluster as usize];
        assert_eq!(game_ct.owner_title_id, 0x00050000_534b4a45);
        assert_eq!(game_ct.group_id, 0x4a45);
        // content/ shaders share the title-owned game content (matching TeconMoon), and it is the
        // LAST content in the package.
        let banner = parsed
            .nodes
            .iter()
            .find(|n| n.name == "banner.gsh")
            .unwrap();
        assert_eq!(
            banner.cluster, hif.cluster,
            "shaders live in the game content"
        );
        assert_eq!(
            hif.cluster as usize,
            parsed.contents.len() - 1,
            "the game content is last"
        );
        // meta.xml is in its own hashed content, before the game content.
        let meta = parsed.nodes.iter().find(|n| n.name == "meta.xml").unwrap();
        assert_ne!(meta.cluster, hif.cluster);
        assert_eq!(parsed.contents[meta.cluster as usize].owner_title_id, 0);
        // Each code file gets its own content (matching retail/TeconMoon layout).
        let app = parsed.nodes.iter().find(|n| n.name == "app.xml").unwrap();
        let cos = parsed.nodes.iter().find(|n| n.name == "cos.xml").unwrap();
        let rpx = parsed
            .nodes
            .iter()
            .find(|n| n.name == "frisbiiU.rpx")
            .unwrap();
        assert_ne!(
            app.cluster, cos.cluster,
            "each code file gets its own content"
        );
        assert_ne!(app.cluster, rpx.cluster);
    }
}
