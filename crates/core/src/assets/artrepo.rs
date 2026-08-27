//! Best-effort download of pre-made boot-texture artwork from the community
//! UWUVCI-IMAGES repository.

use std::time::Duration;

use crate::error::Result;

use super::images::BootTexture;

const REPO_BASE: &str = "https://raw.githubusercontent.com/UWUVCI-PRIME/UWUVCI-IMAGES/master";
const FETCH_TIMEOUT: Duration = Duration::from_secs(30);

/// The PNG filename art repositories store a texture under, or `None` if no repository
/// art exists for that texture (the boot logo has none).
pub fn art_png_name(tex: BootTexture) -> Option<&'static str> {
    match tex {
        BootTexture::Icon => Some("iconTex.png"),
        BootTexture::BootTv => Some("bootTvTex.png"),
        BootTexture::BootDrc => Some("bootDrcTex.png"),
        BootTexture::BootLogo => None,
    }
}

/// Download `tex`'s PNG artwork for `game_id6` from the UWUVCI-IMAGES repository for
/// `system` (e.g. `"wii"`). Returns `Ok(None)` if no repository art exists for this
/// texture, on a 404, or on any network failure.
pub fn download_texture(system: &str, game_id6: &str, tex: BootTexture) -> Result<Option<Vec<u8>>> {
    let Some(png_name) = art_png_name(tex) else {
        return Ok(None);
    };

    let url = format!("{REPO_BASE}/{system}/{game_id6}/{png_name}");

    let client = match reqwest::blocking::Client::builder()
        .timeout(FETCH_TIMEOUT)
        .build()
    {
        Ok(c) => c,
        Err(e) => {
            log::warn!("failed to build HTTP client: {e}");
            return Ok(None);
        }
    };

    let response = match client.get(&url).send() {
        Ok(resp) => resp,
        Err(e) => {
            log::warn!("failed to reach UWUVCI-IMAGES at {url}: {e}");
            return Ok(None);
        }
    };

    if !response.status().is_success() {
        log::warn!("no repository art at {url} (status {})", response.status());
        return Ok(None);
    }

    match response.bytes() {
        Ok(bytes) => Ok(Some(bytes.to_vec())),
        Err(e) => {
            log::warn!("failed to read art response body from {url}: {e}");
            Ok(None)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn maps_texture_to_png_name() {
        assert_eq!(art_png_name(BootTexture::Icon), Some("iconTex.png"));
        assert_eq!(art_png_name(BootTexture::BootTv), Some("bootTvTex.png"));
        assert_eq!(art_png_name(BootTexture::BootDrc), Some("bootDrcTex.png"));
        assert_eq!(art_png_name(BootTexture::BootLogo), None);
    }

    #[test]
    fn builds_expected_url() {
        let system = "wii";
        let id = "RSPE01";
        let png_name = art_png_name(BootTexture::Icon).unwrap();
        let url = format!("{REPO_BASE}/{system}/{id}/{png_name}");
        assert_eq!(
            url,
            "https://raw.githubusercontent.com/UWUVCI-PRIME/UWUVCI-IMAGES/master/wii/RSPE01/iconTex.png"
        );
    }
}
