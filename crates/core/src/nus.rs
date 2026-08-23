//! Downloading a base title from the Nintendo Update Server (NUS / CCS CDN).
//!
//! NUS serves each title's `tmd`, `cetk`, and content files over **plain HTTP** at
//! `http://ccs.cdn.c.shop.nintendowifi.net/ccs/download/<titleID>/<file>`. Content files are
//! encrypted with the title key; the title key itself is not freely served for paid titles,
//! so the caller supplies it (the encrypted form from a title-key database, decrypted here
//! with the Wii U common key). Nothing is bundled.
//!
//! [`NusBase`] downloads the base, decrypts and extracts it (via [`crate::package::extract`]),
//! and presents it through the [`BaseSource`](crate::base::BaseSource) trait like any other
//! base — skipping the base's own `hif_*.nfs`, which the injected game replaces (so those
//! large contents are never even downloaded).

use std::cell::RefCell;
use std::collections::HashMap;
use std::path::Path;
use std::time::Duration;

use crate::base::{finalize_stage, BaseSource, StagedBase};
use crate::error::{Error, Result};
use crate::package::extract::extract_title;
use crate::package::ticket::decrypt_title_key;
use crate::package::tmd::parse_content_records;

/// Default CCS CDN base URL (plain HTTP; content is already encrypted).
pub const DEFAULT_NUS_URL: &str = "http://ccs.cdn.c.shop.nintendowifi.net/ccs/download";

/// A minimal NUS/CCS content client.
pub struct NusClient {
    base_url: String,
    http: reqwest::blocking::Client,
}

impl NusClient {
    /// Create a client using [`DEFAULT_NUS_URL`].
    pub fn new() -> Result<Self> {
        Self::with_base_url(DEFAULT_NUS_URL)
    }

    /// Create a client with a custom base URL (e.g. a mirror).
    pub fn with_base_url(base_url: impl Into<String>) -> Result<Self> {
        let http = reqwest::blocking::Client::builder()
            .user_agent("wiivci")
            .timeout(Duration::from_secs(120))
            .build()
            .map_err(|e| Error::Other(anyhow::anyhow!("building HTTP client: {e}")))?;
        Ok(NusClient {
            base_url: base_url.into().trim_end_matches('/').to_string(),
            http,
        })
    }

    fn get(&self, title_id: u64, file: &str) -> Result<Vec<u8>> {
        let url = format!("{}/{:016x}/{}", self.base_url, title_id, file);
        let resp = self
            .http
            .get(&url)
            .send()
            .map_err(|e| Error::Other(anyhow::anyhow!("GET {url}: {e}")))?;
        if !resp.status().is_success() {
            return Err(Error::Other(anyhow::anyhow!(
                "GET {url}: HTTP {}",
                resp.status()
            )));
        }
        let bytes = resp
            .bytes()
            .map_err(|e| Error::Other(anyhow::anyhow!("reading {url}: {e}")))?;
        Ok(bytes.to_vec())
    }

    /// Download the latest TMD (or a specific `version`).
    pub fn tmd(&self, title_id: u64, version: Option<u32>) -> Result<Vec<u8>> {
        let file = match version {
            Some(v) => format!("tmd.{v}"),
            None => "tmd".to_string(),
        };
        self.get(title_id, &file)
    }

    /// Download one content by its id (NUS names contents by uppercase 8-hex id, no extension).
    pub fn content(&self, title_id: u64, content_id: u32) -> Result<Vec<u8>> {
        self.get(title_id, &format!("{content_id:08X}"))
    }
}

/// A base title obtained by downloading from NUS.
pub struct NusBase {
    title_id: u64,
    enc_title_key: [u8; 16],
    wiiu_common_key: [u8; 16],
    version: Option<u32>,
    client: NusClient,
}

impl NusBase {
    /// Create an NUS-backed base source.
    ///
    /// * `title_id` — the base title id (e.g. `0x00050000101B0700`).
    /// * `enc_title_key` — the 16-byte *encrypted* title key (as found in title-key
    ///   databases); decrypted internally with `wiiu_common_key`.
    /// * `version` — a specific TMD version, or `None` for the latest.
    pub fn new(
        title_id: u64,
        enc_title_key: [u8; 16],
        wiiu_common_key: [u8; 16],
        version: Option<u32>,
        client: NusClient,
    ) -> Self {
        NusBase {
            title_id,
            enc_title_key,
            wiiu_common_key,
            version,
            client,
        }
    }
}

impl BaseSource for NusBase {
    fn stage(&mut self, build_dir: &Path) -> Result<StagedBase> {
        log::info!("downloading base TMD for {:016x} from NUS", self.title_id);
        let tmd = self.client.tmd(self.title_id, self.version)?;
        let records = parse_content_records(&tmd)
            .map_err(|e| Error::UnsupportedDisc(format!("parsing NUS TMD: {e}")))?;

        let title_key =
            decrypt_title_key(&self.wiiu_common_key, self.title_id, &self.enc_title_key);

        // Download each referenced content on demand, once, caching in memory. Contents that
        // hold only the base's hif_*.nfs are never requested (extract skips those files).
        let cache: RefCell<HashMap<u32, Vec<u8>>> = RefCell::new(HashMap::new());
        let reader = |id: u32| -> Result<Vec<u8>> {
            if let Some(bytes) = cache.borrow().get(&id) {
                return Ok(bytes.clone());
            }
            log::info!("downloading content {id:08X} from NUS");
            let bytes = self.client.content(self.title_id, id)?;
            cache.borrow_mut().insert(id, bytes.clone());
            Ok(bytes)
        };

        extract_title(&records, &title_key, &reader, build_dir, |name| {
            name.starts_with("hif_") && name.ends_with(".nfs")
        })?;

        finalize_stage(build_dir)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Live end-to-end NUS test: download + decrypt + extract Rhythm Heaven Fever and confirm
    /// the staged framework files match the `.wua`-staged base in `.dev/base`. Requires network
    /// access to the CCS CDN and `WIIU_COMMON_KEY`; the encrypted title key is read from the
    /// reference ticket. Ignored by default.
    #[test]
    #[ignore = "hits the live NUS CDN; needs .dev/wup_ref, .dev/base and WIIU_COMMON_KEY"]
    fn nus_download_matches_wua_base() {
        let refdir = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../.dev/wup_ref");
        let base = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../.dev/base");
        let tik = match std::fs::read(refdir.join("title.tik")) {
            Ok(t) => t,
            Err(_) => return,
        };
        if !base.join("code/app.xml").exists() {
            return;
        }
        let Ok(hex) = std::env::var("WIIU_COMMON_KEY") else {
            return;
        };
        let mut common = [0u8; 16];
        for i in 0..16 {
            common[i] = u8::from_str_radix(&hex[i * 2..i * 2 + 2], 16).unwrap();
        }
        let title_id = u64::from_be_bytes(tik[0x1DC..0x1E4].try_into().unwrap());
        let mut enc_key = [0u8; 16];
        enc_key.copy_from_slice(&tik[0x1BF..0x1CF]);

        let mut nus = NusBase::new(title_id, enc_key, common, None, NusClient::new().unwrap());
        let out = tempfile::tempdir().unwrap();
        let staged = match nus.stage(out.path()) {
            Ok(s) => s,
            Err(e) => {
                eprintln!("skipping (NUS unreachable?): {e}");
                return;
            }
        };
        // The htk key and the framework files must match the .wua-staged base.
        let base_htk = std::fs::read(base.join("code/htk.bin")).unwrap();
        assert_eq!(staged.htk.as_slice(), base_htk.as_slice());
        for rel in ["code/frisbiiU.rpx", "code/cos.xml", "meta/meta.xml"] {
            let got = std::fs::read(out.path().join(rel)).unwrap();
            let want = std::fs::read(base.join(rel)).unwrap();
            assert_eq!(got, want, "NUS-extracted {rel} differs from the .wua base");
        }
    }
}
