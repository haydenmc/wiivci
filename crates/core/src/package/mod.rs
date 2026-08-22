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

use std::fs;
use std::path::Path;

use crate::error::{Error, Result};
use cert::CertChain;
use content_crypto::{encode_hashed, encode_nonhashed};
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

/// Build a complete installable WUP package from a staged build directory into `out_dir`.
pub fn build_package(build_dir: &Path, out_dir: &Path, params: &PackageParams) -> Result<PackageStats> {
    fs::create_dir_all(out_dir).map_err(|e| Error::io(out_dir, e))?;
    let plan = content::plan(build_dir)?;

    let mut records = Vec::with_capacity(plan.contents.len());
    let mut total_content_bytes = 0u64;

    for c in &plan.contents {
        let plaintext = assemble_content(c, &plan.fst)?;
        let encoded = if c.content_type == content::TYPE_HASHED {
            encode_hashed(&params.title_key, c.index, &plaintext)
        } else {
            encode_nonhashed(&params.title_key, c.index, &plaintext)
        };

        let app_path = out_dir.join(format!("{:08x}.app", c.index));
        fs::write(&app_path, &encoded.data).map_err(|e| Error::io(&app_path, e))?;
        if let Some(h3) = &encoded.h3 {
            let h3_path = out_dir.join(format!("{:08x}.h3", c.index));
            fs::write(&h3_path, h3).map_err(|e| Error::io(&h3_path, e))?;
        }
        total_content_bytes += encoded.size;

        records.push(ContentRecord {
            id: c.index as u32,
            index: c.index,
            content_type: c.content_type,
            size: encoded.size,
            hash: encoded.tmd_hash,
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

    Ok(PackageStats { content_count: plan.contents.len(), total_content_bytes })
}
