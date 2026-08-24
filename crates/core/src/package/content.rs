//! Assigning the staged `code/`, `content/`, `meta/` files to contents and building the FST.
//!
//! The grouping mirrors the structure of a retail Wii-VC title closely enough to install and
//! boot (validated pieces: the FST serializer, TMD/ticket, and content encryption all match
//! retail byte-for-byte). Files are grouped as:
//!
//! * `code/app.xml` + `code/cos.xml` and the remaining non-executable `code/` files →
//!   non-hashed content(s); each `.rpx`/`.rpl` → its own non-hashed content.
//! * all `meta/` files → one hashed content (FST flags 0x0040, group id 0x0400);
//! * `content/` files except the game `hif_*.nfs` → one hashed content (FST flags 0x0400);
//! * each `hif_*.nfs` → its own hashed content (FST flags 0x0400, entry type bit 0x02).

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
    /// Whether this content holds the injected game data (a `hif_*.nfs`). Retail tags these
    /// contents in the FST with the title's own `owner_title_id`/`group_id`; framework contents
    /// carry `owner 0`.
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

fn read_dir_sorted(dir: &Path) -> Result<Vec<std::fs::DirEntry>> {
    let mut entries: Vec<_> = std::fs::read_dir(dir)
        .map_err(|e| Error::io(dir, e))?
        .collect::<std::result::Result<_, _>>()
        .map_err(|e| Error::io(dir, e))?;
    // Case-insensitive by name, matching retail FST ordering.
    entries.sort_by_key(|e| e.file_name().to_string_lossy().to_lowercase());
    Ok(entries)
}

/// Plan the package layout from a staged build directory. `title_id`/`group_id` tag the
/// injected-game contents in the FST, matching retail titles.
pub fn plan(build_dir: &Path, title_id: u64, group_id: u16) -> Result<PackagePlan> {
    // Content 0 is the FST; subsequent contents are allocated as we assign files.
    let mut contents: Vec<PlannedContent> = vec![PlannedContent {
        index: 0,
        content_type: TYPE_NONHASHED,
        files: Vec::new(),
        data_len: 0,
        is_game: false,
    }];

    let new_content = |ct: u16, contents: &mut Vec<PlannedContent>| -> u16 {
        let idx = contents.len() as u16;
        contents.push(PlannedContent {
            index: idx,
            content_type: ct,
            files: Vec::new(),
            data_len: 0,
            is_game: false,
        });
        idx
    };

    // --- code/ ---
    let code_dir = build_dir.join("code");
    let mut code_children = Vec::new();
    if code_dir.is_dir() {
        let code_content = new_content(TYPE_NONHASHED, &mut contents);
        for entry in read_dir_sorted(&code_dir)? {
            let name = entry.file_name().to_string_lossy().into_owned();
            let path = entry.path();
            if !path.is_file() {
                continue;
            }
            let size = entry.metadata().map_err(|e| Error::io(&path, e))?.len();
            let ext = path.extension().and_then(|e| e.to_str()).unwrap_or("");
            let cluster = if ext == "rpx" || ext == "rpl" {
                new_content(TYPE_NONHASHED, &mut contents)
            } else {
                code_content
            };
            code_children.push(Tree::File {
                name,
                path,
                size,
                cluster,
                flags: 0x0000,
                type_flags: 0,
            });
        }
    }

    // --- content/ (recursive; hif_*.nfs each get their own content) ---
    let content_dir = build_dir.join("content");
    let mut content_children = Vec::new();
    if content_dir.is_dir() {
        let assets_content = new_content(TYPE_HASHED, &mut contents);
        content_children = build_content_tree(&content_dir, assets_content, &mut contents)?;
    }

    // --- meta/ ---
    let meta_dir = build_dir.join("meta");
    let mut meta_children = Vec::new();
    if meta_dir.is_dir() {
        let meta_content = new_content(TYPE_HASHED, &mut contents);
        for entry in read_dir_sorted(&meta_dir)? {
            let name = entry.file_name().to_string_lossy().into_owned();
            let path = entry.path();
            if !path.is_file() {
                continue;
            }
            let size = entry.metadata().map_err(|e| Error::io(&path, e))?.len();
            meta_children.push(Tree::File {
                name,
                path,
                size,
                cluster: meta_content,
                flags: 0x0040,
                type_flags: 0,
            });
        }
    }

    // Assemble the root tree (code, content, meta), each a directory.
    let mut root_children = Vec::new();
    if !code_children.is_empty() {
        let cluster = first_cluster(&code_children);
        root_children.push(Tree::Dir {
            name: "code".into(),
            flags: 0x0000,
            children: code_children,
        });
        let _ = cluster;
    }
    if !content_children.is_empty() {
        root_children.push(Tree::Dir {
            name: "content".into(),
            flags: 0x0400,
            children: content_children,
        });
    }
    if !meta_children.is_empty() {
        root_children.push(Tree::Dir {
            name: "meta".into(),
            flags: 0x0040,
            children: meta_children,
        });
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

    // Compute the FST secondary headers. Retail conventions (verified against a retail title,
    // see the module docs and the retail dump):
    //   * content 0 (the FST itself) has a fully-zeroed secondary header;
    //   * data-content offsets are cumulative in 0x8000 sectors, starting *after* the FST;
    //   * the injected-game contents carry the title's own `owner_title_id`/`group_id`, while
    //     framework contents carry `owner 0` (hashed → group 0x400, non-hashed → group 0).
    // The FST's own byte length depends only on the (fixed) count of contents/nodes/names, not on
    // the offset *values*, so we serialize once to measure it, then place data contents after it.
    let build_headers = |base: u32, contents: &[PlannedContent]| -> Vec<FstContent> {
        let mut v = Vec::with_capacity(contents.len());
        let mut cursor = base;
        for (i, c) in contents.iter().enumerate() {
            if i == 0 {
                v.push(FstContent {
                    offset_sectors: 0,
                    size_sectors: 0,
                    owner_title_id: 0,
                    group_id: 0,
                    flags: 0,
                });
                continue;
            }
            let size_sectors = (align_up(c.data_len.max(1), SECTOR) / SECTOR) as u32;
            let (owner, group, flags) = if c.is_game {
                (title_id, group_id as u32, 0x0200u16)
            } else if c.content_type == TYPE_HASHED {
                (0, 0x0400, 0x0200)
            } else {
                (0, 0x0000, 0x0100)
            };
            v.push(FstContent {
                offset_sectors: cursor,
                size_sectors,
                owner_title_id: owner,
                group_id: group,
                flags,
            });
            cursor += size_sectors;
        }
        v
    };

    // Pass 1: measure the serialized FST length (offset values don't affect the byte length).
    let probe = Fst {
        offset_factor: OFFSET_FACTOR,
        contents: build_headers(0, &contents),
        nodes: nodes.clone(),
    };
    let fst_sectors = (align_up(probe.serialize().len() as u64, SECTOR) / SECTOR) as u32;

    // Pass 2: place data contents right after the FST region.
    let fst = Fst {
        offset_factor: OFFSET_FACTOR,
        contents: build_headers(fst_sectors, &contents),
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

fn first_cluster(children: &[Tree]) -> u16 {
    for c in children {
        match c {
            Tree::File { cluster, .. } => return *cluster,
            Tree::Dir { children, .. } => {
                if let Some(cl) = children.first().map(|_| first_cluster(children)) {
                    return cl;
                }
            }
        }
    }
    0
}

fn build_content_tree(
    dir: &Path,
    assets_content: u16,
    contents: &mut Vec<PlannedContent>,
) -> Result<Vec<Tree>> {
    let mut out = Vec::new();
    for entry in read_dir_sorted(dir)? {
        let name = entry.file_name().to_string_lossy().into_owned();
        let path = entry.path();
        if path.is_dir() {
            let children = build_content_tree(&path, assets_content, contents)?;
            out.push(Tree::Dir {
                name,
                flags: 0x0400,
                children,
            });
        } else {
            let size = entry.metadata().map_err(|e| Error::io(&path, e))?.len();
            let (cluster, type_flags) = if is_hif(&name) {
                let idx = contents.len() as u16;
                contents.push(PlannedContent {
                    index: idx,
                    content_type: TYPE_HASHED,
                    files: Vec::new(),
                    data_len: 0,
                    is_game: true,
                });
                (idx, 0x02)
            } else {
                (assets_content, 0x00)
            };
            out.push(Tree::File {
                name,
                path,
                size,
                cluster,
                flags: 0x0400,
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

        let title_id = 0x0005_0002_5253_5045u64;
        let group_id = 0x5045u16;
        let plan = plan(root, title_id, group_id).unwrap();
        // FST content + code content + rpx content + assets content + hif content + meta content
        assert!(plan.contents.len() >= 6);
        assert!(!plan.fst.is_empty());

        // FST must round-trip and contain the expected files.
        let parsed = Fst::parse(&plan.fst).unwrap();

        // Content 0 (the FST itself) has a fully-zeroed secondary header (retail convention).
        let c0 = &parsed.contents[0];
        assert_eq!(c0.size_sectors, 0);
        assert_eq!(c0.flags, 0);
        assert_eq!(c0.group_id, 0);
        assert_eq!(c0.owner_title_id, 0);

        // The hif (game) content is tagged with the title's own owner/group; framework contents
        // are not.
        let hif_node = parsed
            .nodes
            .iter()
            .find(|n| n.name == "hif_000000.nfs")
            .unwrap();
        let hif = &parsed.contents[hif_node.cluster as usize];
        assert_eq!(
            hif.owner_title_id, title_id,
            "game content owner = title id"
        );
        assert_eq!(
            hif.group_id, group_id as u32,
            "game content group = title group"
        );
        // A framework content (content 1) is owned by nobody.
        assert_eq!(parsed.contents[1].owner_title_id, 0);

        // Data contents are placed after the FST region (offset 0 is only the FST's slot).
        assert!(parsed.contents[1].offset_sectors >= 1);
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
        // app.xml and cos.xml share the code content; frisbiiU.rpx is separate.
        let app = parsed.nodes.iter().find(|n| n.name == "app.xml").unwrap();
        let cos = parsed.nodes.iter().find(|n| n.name == "cos.xml").unwrap();
        let rpx = parsed
            .nodes
            .iter()
            .find(|n| n.name == "frisbiiU.rpx")
            .unwrap();
        assert_eq!(app.cluster, cos.cluster);
        assert_ne!(app.cluster, rpx.cluster);
    }
}
