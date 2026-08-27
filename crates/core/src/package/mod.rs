//! Assembly of the installable WUP package (title.tmd/tik/cert + `.app`/`.h3`).
//!
//! Given a build directory containing the staged `code/`, `content/` and `meta/` trees, the
//! packager assigns files to contents, builds the FST, encrypts each content (with H0–H3
//! hash trees for hashed contents), and emits the TMD, ticket and certificate chain.

pub mod cert;
pub mod content;
pub mod content_crypto;
pub mod extract;
pub mod fst;
pub mod ticket;
pub mod tmd;

use std::fs::{self, File};
use std::io::{BufWriter, Read, Seek, SeekFrom, Write};
use std::path::Path;

use crate::error::{Error, Result};
use cert::CertChain;
use content_crypto::{encode_hashed_to_writer, encode_nonhashed};
use tmd::ContentRecord;

/// Parameters for building a WUP package.
pub struct PackageParams<'a> {
    /// Wii U title id (`00050002<disc4hex>`).
    pub title_id: u64,
    /// TMD group id (2 bytes).
    pub group_id: u16,
    /// The Wii U common key, for encrypting the title key into the ticket.
    pub wiiu_common_key: [u8; 16],
    /// The (decrypted) title key used to encrypt content.
    pub title_key: [u8; 16],
    /// The certificate chain to emit as `title.cert`.
    pub cert: &'a CertChain,
}

/// Statistics about a built package.
#[derive(Debug, Clone)]
pub struct PackageStats {
    /// Number of contents written (including the FST).
    pub content_count: usize,
    /// Total bytes of encrypted content written.
    pub total_content_bytes: u64,
}

/// Assemble one content's decrypted bytes by placing its files at their offsets.
///
/// Used for the small non-hashed contents (and the FST); large hashed contents are streamed via
/// [`ContentPlaintextReader`] instead of buffered here.
fn assemble_content(c: &content::PlannedContent, fst: &[u8]) -> Result<Vec<u8>> {
    if c.index == 0 {
        return Ok(fst.to_vec());
    }
    let mut buf = vec![0u8; c.data_len as usize];
    for f in &c.files {
        let bytes = fs::read(&f.path).map_err(|e| Error::io(&f.path, e))?;
        let start = f.offset as usize;
        buf[start..start + bytes.len()].copy_from_slice(&bytes);
    }
    Ok(buf)
}

/// A `Read` that streams a content's decrypted plaintext — the exact bytes [`assemble_content`]
/// would produce (files at their `offset`s, alignment gaps zero-filled, total `data_len`) — without
/// buffering the whole content or any whole file. This lets large hashed game contents be encoded
/// straight to disk. Files are read sequentially, one open at a time.
struct ContentPlaintextReader {
    files: Vec<content::PlacedFile>, // ascending, non-overlapping by offset
    data_len: u64,
    pos: u64,
    file_idx: usize,
    open: Option<File>,
}

impl ContentPlaintextReader {
    fn new(c: &content::PlannedContent) -> Self {
        let mut files = c.files.clone();
        files.sort_by_key(|f| f.offset);
        ContentPlaintextReader {
            files,
            data_len: c.data_len,
            pos: 0,
            file_idx: 0,
            open: None,
        }
    }
}

impl Read for ContentPlaintextReader {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        if self.pos >= self.data_len || buf.is_empty() {
            return Ok(0);
        }
        // Skip any files we've fully passed (defensive; reads are sequential).
        while let Some(f) = self.files.get(self.file_idx) {
            if self.pos >= f.offset + f.size {
                self.file_idx += 1;
                self.open = None;
            } else {
                break;
            }
        }
        let want = buf.len().min((self.data_len - self.pos) as usize);
        match self.files.get(self.file_idx) {
            // A gap before the next file: emit zeros up to its offset.
            Some(f) if self.pos < f.offset => {
                let n = want.min((f.offset - self.pos) as usize);
                buf[..n].fill(0);
                self.pos += n as u64;
                Ok(n)
            }
            // Inside the current file's region: stream from it.
            Some(f) => {
                let (foff, fsize) = (f.offset, f.size);
                if self.open.is_none() {
                    let mut fh = File::open(&self.files[self.file_idx].path)?;
                    fh.seek(SeekFrom::Start(self.pos - foff))?;
                    self.open = Some(fh);
                }
                let n = want.min((foff + fsize - self.pos) as usize);
                self.open.as_mut().unwrap().read_exact(&mut buf[..n])?;
                self.pos += n as u64;
                if self.pos >= foff + fsize {
                    self.open = None;
                    self.file_idx += 1;
                }
                Ok(n)
            }
            // Trailing gap after the last file, up to data_len.
            None => {
                let n = want;
                buf[..n].fill(0);
                self.pos += n as u64;
                Ok(n)
            }
        }
    }
}

/// Build a complete installable WUP package from a staged build directory into `out_dir`.
pub fn build_package(
    build_dir: &Path,
    out_dir: &Path,
    params: &PackageParams,
) -> Result<PackageStats> {
    fs::create_dir_all(out_dir).map_err(|e| Error::io(out_dir, e))?;
    let plan = content::plan(build_dir, params.title_id)?;

    let mut records = Vec::with_capacity(plan.contents.len());
    let mut total_content_bytes = 0u64;

    for c in &plan.contents {
        let app_path = out_dir.join(format!("{:08x}.app", c.index));
        let (size, tmd_hash) = if c.content_type == content::TYPE_HASHED {
            // Large game contents: stream the plaintext straight to the encrypted .app one hash
            // group at a time, so we never buffer the whole content in memory.
            let file = File::create(&app_path).map_err(|e| Error::io(&app_path, e))?;
            let mut writer = BufWriter::new(file);
            let reader = ContentPlaintextReader::new(c);
            let summary = encode_hashed_to_writer(&params.title_key, c.index, reader, &mut writer)
                .map_err(|e| Error::io(&app_path, e))?;
            writer.flush().map_err(|e| Error::io(&app_path, e))?;
            let h3_path = out_dir.join(format!("{:08x}.h3", c.index));
            fs::write(&h3_path, &summary.h3).map_err(|e| Error::io(&h3_path, e))?;
            (summary.size, summary.tmd_hash)
        } else {
            // Small non-hashed contents (and the FST): assemble in memory (no .h3).
            let plaintext = assemble_content(c, &plan.fst)?;
            let encoded = encode_nonhashed(&params.title_key, c.index, &plaintext);
            fs::write(&app_path, &encoded.data).map_err(|e| Error::io(&app_path, e))?;
            (encoded.size, encoded.tmd_hash)
        };
        total_content_bytes += size;

        records.push(ContentRecord {
            id: c.index as u32,
            index: c.index,
            content_type: c.content_type,
            size,
            hash: tmd_hash,
        });
    }

    // TMD, ticket, cert.
    let tmd_bytes = tmd::build_tmd(params.title_id, params.group_id, &records);
    fs::write(out_dir.join("title.tmd"), &tmd_bytes)
        .map_err(|e| Error::io(out_dir.join("title.tmd"), e))?;

    let enc_title_key =
        ticket::encrypt_title_key(&params.wiiu_common_key, params.title_id, &params.title_key);
    let tik_bytes = ticket::build_ticket(params.title_id, &enc_title_key);
    fs::write(out_dir.join("title.tik"), &tik_bytes)
        .map_err(|e| Error::io(out_dir.join("title.tik"), e))?;

    fs::write(out_dir.join("title.cert"), params.cert.as_bytes())
        .map_err(|e| Error::io(out_dir.join("title.cert"), e))?;

    Ok(PackageStats {
        content_count: plan.contents.len(),
        total_content_bytes,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use content::{PlacedFile, PlannedContent, TYPE_HASHED};

    /// The streaming reader must reproduce `assemble_content`'s buffer byte-for-byte, including the
    /// zero-filled alignment gaps between files and the trailing gap up to `data_len`.
    #[test]
    fn content_plaintext_reader_matches_assemble_content() {
        let dir = tempfile::tempdir().unwrap();
        // Three files at non-adjacent 0x20-aligned offsets → gaps before/between/after.
        let mk = |name: &str, byte: u8, len: usize| {
            let p = dir.path().join(name);
            std::fs::write(&p, vec![byte; len]).unwrap();
            (p, len as u64)
        };
        let (p0, s0) = mk("a.bin", 0xAA, 100);
        let (p1, s1) = mk("b.bin", 0xBB, 0x40);
        let (p2, s2) = mk("c.bin", 0xCC, 7);
        let files = vec![
            PlacedFile {
                path: p0,
                offset: 0x20,
                size: s0,
            }, // gap [0,0x20)
            PlacedFile {
                path: p1,
                offset: 0x100,
                size: s1,
            }, // gap after a.bin
            PlacedFile {
                path: p2,
                offset: 0x200,
                size: s2,
            },
        ];
        let data_len = 0x240; // trailing gap after c.bin
        let c = PlannedContent {
            index: 5,
            content_type: TYPE_HASHED,
            files,
            data_len,
            is_game: true,
        };

        let expected = assemble_content(&c, &[]).unwrap();
        assert_eq!(expected.len(), data_len as usize);

        let mut got = Vec::new();
        ContentPlaintextReader::new(&c)
            .read_to_end(&mut got)
            .unwrap();
        assert_eq!(
            got, expected,
            "streamed plaintext must match assemble_content"
        );

        // Also check it works with a tiny read buffer (forces many short reads across boundaries).
        let mut reader = ContentPlaintextReader::new(&c);
        let mut got2 = Vec::new();
        let mut small = [0u8; 3];
        loop {
            let n = reader.read(&mut small).unwrap();
            if n == 0 {
                break;
            }
            got2.extend_from_slice(&small[..n]);
        }
        assert_eq!(got2, expected, "small-buffer reads must also match");
    }
}
