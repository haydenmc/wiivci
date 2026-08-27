//! Decrypting and extracting a WUP title's files (the inverse of [`super::build_package`]).
//!
//! Given a title's content records (from its TMD), a decrypted title key, and a way to read
//! each encrypted content `.app`, this decodes the FST (content index 0), maps every file to
//! its content/offset/size, and writes the files back out under their `code/`/`content/`/
//! `meta/` paths — the same algorithm as CDecrypt. Used to turn an NUS download into a staged
//! base title.

use std::collections::HashMap;
use std::path::Path;

use crate::base::safe_join;
use crate::error::{Error, Result};

use super::content::TYPE_HASHED;
use super::content_crypto::{decode_hashed, decode_nonhashed, hashed_tmd_hash, nonhashed_tmd_hash};
use super::fst::{Fst, FstNodeKind};
use super::tmd::ContentRecord;

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

/// Decrypt a single content to its logical (hash-stripped) data, then verify it against the
/// SHA-1 hash recorded for it in the TMD — the only integrity check an NUS download (fetched over
/// plain HTTP) or a user-supplied `.app` file otherwise gets. For hashed (`0x2003`) content the
/// TMD hash covers the `.h3` (recomputed here from the decoded plaintext, mirroring the hash-tree
/// logic the encode side uses to derive it); for non-hashed (`0x2001`) content it covers the
/// padded plaintext directly (see [`super::content_crypto`] and [`super::tmd`]).
fn decode_content(rec: &ContentRecord, title_key: &[u8; 16], cipher: &[u8]) -> Result<Vec<u8>> {
    let (data, actual_hash) = if rec.content_type == TYPE_HASHED {
        let data = decode_hashed(title_key, rec.index, cipher)?;
        let hash = hashed_tmd_hash(&data);
        (data, hash)
    } else {
        let data = decode_nonhashed(title_key, rec.index, cipher)?;
        let hash = nonhashed_tmd_hash(&data);
        (data, hash)
    };
    if actual_hash != rec.hash {
        return Err(Error::UnsupportedDisc(format!(
            "content {:08x} (index {}) failed TMD hash verification — corrupted or tampered download",
            rec.id, rec.index
        )));
    }
    Ok(data)
}

/// Reconstruct each FST node's full path (root is ""). Directories included.
fn node_paths(fst: &Fst) -> Vec<String> {
    let mut paths = vec![String::new(); fst.nodes.len()];
    // Stack of (end_index, path) for the currently-open directories.
    let mut stack: Vec<(u32, String)> = Vec::new();
    if let Some(FstNodeKind::Dir { end_index, .. }) = fst.nodes.first().map(|n| &n.kind) {
        stack.push((*end_index, String::new()));
    }
    for (i, node) in fst.nodes.iter().enumerate().skip(1) {
        while let Some(&(end, _)) = stack.last() {
            if i as u32 >= end {
                stack.pop();
            } else {
                break;
            }
        }
        let parent = stack.last().map(|(_, p)| p.as_str()).unwrap_or("");
        let path = if parent.is_empty() {
            node.name.clone()
        } else {
            format!("{parent}/{}", node.name)
        };
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
    let fst_rec = by_index
        .get(&0)
        .ok_or_else(|| Error::UnsupportedDisc("title has no FST content".into()))?;
    let fst_cipher = reader.read(fst_rec.id)?;
    let fst_data = decode_content(fst_rec, title_key, &fst_cipher)?;
    let fst = Fst::parse(&fst_data)
        .ok_or_else(|| Error::UnsupportedDisc("could not parse title FST".into()))?;

    let paths = node_paths(&fst);
    let mut decoded_cache: HashMap<u16, Vec<u8>> = HashMap::new();

    for (i, node) in fst.nodes.iter().enumerate() {
        let rel = &paths[i];
        match node.kind {
            FstNodeKind::Dir { .. } => {
                if !rel.is_empty() {
                    let dir = safe_join(out_dir, rel)?;
                    std::fs::create_dir_all(&dir).map_err(|e| Error::io(&dir, e))?;
                }
            }
            FstNodeKind::File { offset, size } => {
                if skip_file(&node.name) {
                    continue;
                }
                let rec = by_index.get(&node.cluster).ok_or_else(|| {
                    Error::UnsupportedDisc(format!(
                        "FST references missing content {}",
                        node.cluster
                    ))
                })?;
                let data = match decoded_cache.get(&node.cluster) {
                    Some(d) => d,
                    None => {
                        let cipher = reader.read(rec.id)?;
                        let d = decode_content(rec, title_key, &cipher)?;
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
                let path = safe_join(out_dir, rel)?;
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
    use crate::package::content::TYPE_NONHASHED;
    use crate::package::content_crypto::{encode_hashed, encode_nonhashed};
    use crate::package::fst::FstNode;
    use crate::package::tmd::parse_content_records;

    /// Build a minimal two-content title (content 0 = non-hashed FST, content 1 = hashed file
    /// data) and its TMD content records, entirely in memory.
    fn tiny_title(
        title_key: &[u8; 16],
        file_data: &[u8],
    ) -> (Vec<ContentRecord>, Vec<u8>, Vec<u8>) {
        let fst = Fst {
            offset_factor: 0x20,
            contents: vec![],
            nodes: vec![
                FstNode {
                    name: String::new(),
                    kind: FstNodeKind::Dir {
                        parent_index: 0,
                        end_index: 2,
                    },
                    type_flags: 0,
                    flags: 0,
                    cluster: 0,
                },
                FstNode {
                    name: "hello.txt".into(),
                    kind: FstNodeKind::File {
                        offset: 0,
                        size: file_data.len() as u64,
                    },
                    type_flags: 0,
                    flags: 0,
                    cluster: 1,
                },
            ],
        };
        let fst_bytes = fst.serialize();
        let enc0 = encode_nonhashed(title_key, 0, &fst_bytes);
        let enc1 = encode_hashed(title_key, 1, file_data);
        let records = vec![
            ContentRecord {
                id: 0,
                index: 0,
                content_type: TYPE_NONHASHED,
                size: enc0.size,
                hash: enc0.tmd_hash,
            },
            ContentRecord {
                id: 1,
                index: 1,
                content_type: TYPE_HASHED,
                size: enc1.size,
                hash: enc1.tmd_hash,
            },
        ];
        (records, enc0.data, enc1.data)
    }

    /// End-to-end proof that TMD-hash verification is wired into `extract_title`: well-formed
    /// content extracts cleanly, and a single flipped byte in the (hashed) file content's
    /// ciphertext is caught as a hash mismatch instead of silently producing corrupted output.
    #[test]
    fn extract_title_verifies_tmd_hash() {
        let title_key = [0x5Au8; 16];
        let file_data = b"hello".to_vec();
        let (records, content0, content1) = tiny_title(&title_key, &file_data);

        // Well-formed: extraction succeeds and the file matches.
        let reader = |id: u32| -> Result<Vec<u8>> {
            Ok(match id {
                0 => content0.clone(),
                1 => content1.clone(),
                _ => unreachable!(),
            })
        };
        let out = tempfile::tempdir().unwrap();
        extract_title(&records, &title_key, &reader, out.path(), |_| false).unwrap();
        assert_eq!(
            std::fs::read(out.path().join("hello.txt")).unwrap(),
            file_data
        );

        // Tampered: flip a byte in content 1's ciphertext (past the hash header, in the
        // encrypted data region) and confirm extraction now fails with a hash-mismatch error
        // naming the content, instead of writing corrupted bytes.
        let mut tampered1 = content1.clone();
        let flip_at = tampered1.len() - 1;
        tampered1[flip_at] ^= 0xFF;
        let bad_reader = |id: u32| -> Result<Vec<u8>> {
            Ok(match id {
                0 => content0.clone(),
                1 => tampered1.clone(),
                _ => unreachable!(),
            })
        };
        let out2 = tempfile::tempdir().unwrap();
        let err =
            extract_title(&records, &title_key, &bad_reader, out2.path(), |_| false).unwrap_err();
        assert!(
            err.to_string().contains("TMD hash verification"),
            "unexpected error: {err}"
        );
    }

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
            Err(_) => {
                eprintln!(
                    "skipping extracts_retail_matching_wua: {} not present",
                    dir.join("title.tmd").display()
                );
                return;
            }
        };
        if !base.join("code/app.xml").exists() {
            eprintln!(
                "skipping extracts_retail_matching_wua: {} not present (run the stage_base example to populate .dev/base)",
                base.join("code/app.xml").display()
            );
            return;
        }
        let Ok(hex) = std::env::var("WIIU_COMMON_KEY") else {
            eprintln!("skipping extracts_retail_matching_wua: WIIU_COMMON_KEY not present");
            return;
        };
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
        extract_title(&records, &title_key, &reader, out.path(), |n| {
            n.starts_with("hif_")
        })
        .unwrap();

        // Every extracted file must byte-match the zarust-staged base (which also omits hif).
        for rel in [
            "code/app.xml",
            "code/frisbiiU.rpx",
            "code/cos.xml",
            "code/htk.bin",
            "meta/meta.xml",
            "content/assets/shaders/cafe/banner.gsh",
        ] {
            let extracted =
                std::fs::read(out.path().join(rel)).unwrap_or_else(|_| panic!("missing {rel}"));
            let expected = std::fs::read(base.join(rel)).unwrap();
            assert_eq!(
                extracted, expected,
                "extracted {rel} differs from the .wua-staged base"
            );
        }
    }

    #[test]
    fn node_paths_reconstructs_tree() {
        use super::super::fst::{FstContent, FstNode};
        let fst = Fst {
            offset_factor: 0x20,
            contents: vec![FstContent {
                offset_sectors: 0,
                size_sectors: 0,
                owner_title_id: 0,
                group_id: 0,
                flags: 0x0100,
            }],
            nodes: vec![
                FstNode {
                    name: "".into(),
                    kind: FstNodeKind::Dir {
                        parent_index: 0,
                        end_index: 4,
                    },
                    type_flags: 0,
                    flags: 0,
                    cluster: 0,
                },
                FstNode {
                    name: "code".into(),
                    kind: FstNodeKind::Dir {
                        parent_index: 0,
                        end_index: 3,
                    },
                    type_flags: 0,
                    flags: 0,
                    cluster: 0,
                },
                FstNode {
                    name: "app.xml".into(),
                    kind: FstNodeKind::File { offset: 0, size: 6 },
                    type_flags: 0,
                    flags: 0,
                    cluster: 0,
                },
                FstNode {
                    name: "meta".into(),
                    kind: FstNodeKind::Dir {
                        parent_index: 0,
                        end_index: 4,
                    },
                    type_flags: 0,
                    flags: 0,
                    cluster: 0,
                },
            ],
        };
        let paths = node_paths(&fst);
        assert_eq!(paths[1], "code");
        assert_eq!(paths[2], "code/app.xml");
        assert_eq!(paths[3], "meta");
    }
}
