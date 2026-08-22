//! Decrypting and extracting a WUP title's files (the inverse of [`super::build_package`]).
//!
//! Given a title's content records (from its TMD), a decrypted title key, and a way to read
//! each encrypted content `.app`, this decodes the FST (content index 0), maps every file to
//! its content/offset/size, and writes the files back out under their `code/`/`content/`/
//! `meta/` paths — the same algorithm as CDecrypt. Used to turn an NUS download into a staged
//! base title.

use std::collections::HashMap;
use std::path::Path;

use crate::error::{Error, Result};

use super::content_crypto::{decode_hashed, decode_nonhashed};
use super::fst::{Fst, FstNodeKind};
use super::tmd::ContentRecord;
use super::content::TYPE_HASHED;

/// Reads the encrypted `.app` bytes for a given content id.
pub trait ContentReader {
    /// Return the encrypted content bytes for content `id`.
    fn read(&self, id: u32) -> Result<Vec<u8>>;
}

impl<F: Fn(u32) -> Result<Vec<u8>>> ContentReader for F {
    fn read(&self, id: u32) -> Result<Vec<u8>> {
        self(id)
    }
}

/// Decrypt a single content to its logical (hash-stripped) data.
fn decode_content(rec: &ContentRecord, title_key: &[u8; 16], cipher: &[u8]) -> Vec<u8> {
    if rec.content_type == TYPE_HASHED {
        decode_hashed(title_key, rec.index, cipher)
    } else {
        decode_nonhashed(title_key, rec.index, cipher)
    }
}

/// Reconstruct each FST node's full path (root is ""). Directories included.
fn node_paths(fst: &Fst) -> Vec<String> {
    let mut paths = vec![String::new(); fst.nodes.len()];
    // Stack of (end_index, path) for the currently-open directories.
    let mut stack: Vec<(u32, String)> = Vec::new();
    if let Some(FstNodeKind::Dir { end_index, .. }) = fst.nodes.first().map(|n| &n.kind) {
        stack.push((*end_index, String::new()));
    }
    for i in 1..fst.nodes.len() {
        while let Some(&(end, _)) = stack.last() {
            if i as u32 >= end {
                stack.pop();
            } else {
                break;
            }
        }
        let parent = stack.last().map(|(_, p)| p.as_str()).unwrap_or("");
        let node = &fst.nodes[i];
        let path = if parent.is_empty() { node.name.clone() } else { format!("{parent}/{}", node.name) };
        paths[i] = path.clone();
        if let FstNodeKind::Dir { end_index, .. } = node.kind {
            stack.push((end_index, path));
        }
    }
    paths
}

/// Decrypt and extract all files into `out_dir`. `skip_file` receives each file's base name
/// and returns true to skip writing it (e.g. the base's own `hif_*.nfs`).
pub fn extract_title(
    records: &[ContentRecord],
    title_key: &[u8; 16],
    reader: &dyn ContentReader,
    out_dir: &Path,
    skip_file: impl Fn(&str) -> bool,
) -> Result<()> {
    let by_index: HashMap<u16, &ContentRecord> = records.iter().map(|r| (r.index, r)).collect();

    // Content index 0 is the FST.
    let fst_rec = by_index.get(&0).ok_or_else(|| Error::UnsupportedDisc("title has no FST content".into()))?;
    let fst_cipher = reader.read(fst_rec.id)?;
    let fst_data = decode_content(fst_rec, title_key, &fst_cipher);
    let fst = Fst::parse(&fst_data).ok_or_else(|| Error::UnsupportedDisc("could not parse title FST".into()))?;

    let paths = node_paths(&fst);
    let mut decoded_cache: HashMap<u16, Vec<u8>> = HashMap::new();

    for (i, node) in fst.nodes.iter().enumerate() {
        let rel = &paths[i];
        match node.kind {
            FstNodeKind::Dir { .. } => {
                if !rel.is_empty() {
                    let dir = out_dir.join(rel);
                    std::fs::create_dir_all(&dir).map_err(|e| Error::io(&dir, e))?;
                }
            }
            FstNodeKind::File { offset, size } => {
                if skip_file(&node.name) {
                    continue;
                }
                let rec = by_index.get(&node.cluster).ok_or_else(|| {
                    Error::UnsupportedDisc(format!("FST references missing content {}", node.cluster))
                })?;
                let data = match decoded_cache.get(&node.cluster) {
                    Some(d) => d,
                    None => {
                        let cipher = reader.read(rec.id)?;
                        let d = decode_content(rec, title_key, &cipher);
                        decoded_cache.entry(node.cluster).or_insert(d)
                    }
                };
                let (start, end) = (offset as usize, (offset + size) as usize);
                if end > data.len() {
                    return Err(Error::UnsupportedDisc(format!(
                        "file {rel} extends past its content ({end} > {})",
                        data.len()
                    )));
                }
                let path = out_dir.join(rel);
                if let Some(parent) = path.parent() {
                    std::fs::create_dir_all(parent).map_err(|e| Error::io(parent, e))?;
                }
                std::fs::write(&path, &data[start..end]).map_err(|e| Error::io(&path, e))?;
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::package::tmd::parse_content_records;

    /// Extract a retail WUP (from .dev/wup_ref, needing title.tmd/tik + content .app 00..10;
    /// the hif contents 11/12 are skipped so aren't required) and confirm the extracted files
    /// match the base staged from the `.wua` in .dev/base byte-for-byte. This cross-validates
    /// the whole decrypt→FST→extract path against the independent zarust path. Needs
    /// WIIU_COMMON_KEY. Ignored by default.
    #[test]
    #[ignore = "needs .dev/wup_ref/*.app, .dev/base, and WIIU_COMMON_KEY"]
    fn extracts_retail_matching_wua() {
        let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../.dev/wup_ref");
        let base = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../.dev/base");
        let tmd = match std::fs::read(dir.join("title.tmd")) {
            Ok(t) => t,
            Err(_) => return,
        };
        if !base.join("code/app.xml").exists() {
            eprintln!("skipping: run the stage_base example to populate .dev/base");
            return;
        }
        let Ok(hex) = std::env::var("WIIU_COMMON_KEY") else { return };
        let mut common = [0u8; 16];
        for i in 0..16 {
            common[i] = u8::from_str_radix(&hex[i * 2..i * 2 + 2], 16).unwrap();
        }
        // Derive the retail title key from the ticket.
        let tik = std::fs::read(dir.join("title.tik")).unwrap();
        let title_id = u64::from_be_bytes(tik[0x1DC..0x1E4].try_into().unwrap());
        let mut iv = [0u8; 16];
        iv[..8].copy_from_slice(&title_id.to_be_bytes());
        let mut title_key = [0u8; 16];
        title_key.copy_from_slice(&tik[0x1BF..0x1CF]);
        use aes::cipher::{block_padding::NoPadding, BlockDecryptMut, KeyIvInit};
        <cbc::Decryptor<aes::Aes128>>::new(&common.into(), &iv.into())
            .decrypt_padded_mut::<NoPadding>(&mut title_key)
            .unwrap();

        let records = parse_content_records(&tmd).unwrap();
        let reader = |id: u32| -> Result<Vec<u8>> {
            let p = dir.join(format!("{id:08x}.app"));
            std::fs::read(&p).map_err(|e| Error::io(&p, e))
        };
        let out = tempfile::tempdir().unwrap();
        extract_title(&records, &title_key, &reader, out.path(), |n| n.starts_with("hif_")).unwrap();

        // Every extracted file must byte-match the zarust-staged base (which also omits hif).
        for rel in ["code/app.xml", "code/frisbiiU.rpx", "code/cos.xml", "code/htk.bin",
                    "meta/meta.xml", "content/assets/shaders/cafe/banner.gsh"] {
            let extracted = std::fs::read(out.path().join(rel)).unwrap_or_else(|_| panic!("missing {rel}"));
            let expected = std::fs::read(base.join(rel)).unwrap();
            assert_eq!(extracted, expected, "extracted {rel} differs from the .wua-staged base");
        }
    }

    #[test]
    fn node_paths_reconstructs_tree() {
        use super::super::fst::{FstContent, FstNode};
        let fst = Fst {
            offset_factor: 0x20,
            contents: vec![FstContent { offset_sectors: 0, size_sectors: 0, owner_title_id: 0, group_id: 0, flags: 0x0100 }],
            nodes: vec![
                FstNode { name: "".into(), kind: FstNodeKind::Dir { parent_index: 0, end_index: 4 }, type_flags: 0, flags: 0, cluster: 0 },
                FstNode { name: "code".into(), kind: FstNodeKind::Dir { parent_index: 0, end_index: 3 }, type_flags: 0, flags: 0, cluster: 0 },
                FstNode { name: "app.xml".into(), kind: FstNodeKind::File { offset: 0, size: 6 }, type_flags: 0, flags: 0, cluster: 0 },
                FstNode { name: "meta".into(), kind: FstNodeKind::Dir { parent_index: 0, end_index: 4 }, type_flags: 0, flags: 0, cluster: 0 },
            ],
        };
        let paths = node_paths(&fst);
        assert_eq!(paths[1], "code");
        assert_eq!(paths[2], "code/app.xml");
        assert_eq!(paths[3], "meta");
    }
}
