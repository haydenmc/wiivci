//! Fetching the Nintendont loader (`boot.dol`), used as the synthetic Wii disc's `main.dol` when
//! injecting a GameCube game.
//!
//! Nintendont is free homebrew (FIX94/Nintendont, GPL). We pin a specific build so results are
//! reproducible; the user can override with a locally-supplied `boot.dol` (and must, when offline).

use std::time::Duration;

use anyhow::{anyhow, Context};

use crate::error::{Error, Result};

const FETCH_TIMEOUT: Duration = Duration::from_secs(30);

/// The pinned Nintendont loader.
///
/// NOTE: pin this to a specific, verified commit/tag of FIX94/Nintendont before relying on it for a
/// release — the loader is rolling on `master`. The committed `loader/loader.dol` is the built
/// binary distributed as Nintendont's `boot.dol`.
pub const NINTENDONT_LOADER_URL: &str =
    "https://raw.githubusercontent.com/FIX94/Nintendont/master/loader/loader.dol";

/// A loose sanity floor for a real Nintendont loader (it is well over 1 MiB); guards against
/// silently accepting an HTML error page.
const MIN_LOADER_BYTES: usize = 512 * 1024;

/// Download the pinned Nintendont loader `boot.dol`. Errors on any network/HTTP failure or an
/// implausibly small response, so callers can fall back to a user-supplied file.
pub fn download_boot_dol() -> Result<Vec<u8>> {
    let url = NINTENDONT_LOADER_URL;
    log::info!("downloading Nintendont loader from {url}");
    let client = reqwest::blocking::Client::builder()
        .timeout(FETCH_TIMEOUT)
        .build()
        .context("building HTTP client")
        .map_err(Error::Other)?;
    let response = client
        .get(url)
        .send()
        .with_context(|| format!("fetching Nintendont loader from {url}"))
        .map_err(Error::Other)?;
    if !response.status().is_success() {
        return Err(Error::Other(anyhow!(
            "Nintendont download failed: {url} returned {}",
            response.status()
        )));
    }
    let bytes = response
        .bytes()
        .with_context(|| format!("reading Nintendont loader body from {url}"))
        .map_err(Error::Other)?
        .to_vec();
    if bytes.len() < MIN_LOADER_BYTES {
        return Err(Error::Other(anyhow!(
            "Nintendont download from {url} was only {} bytes (expected a >1 MiB boot.dol); \
             supply one with --nintendont",
            bytes.len()
        )));
    }
    Ok(bytes)
}
