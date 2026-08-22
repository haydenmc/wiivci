//! Best-effort game title lookup against GameTDB's flat `wiitdb.txt` database.

use std::path::PathBuf;

use crate::error::Result;

const WIITDB_URL: &str = "https://www.gametdb.com/wiitdb.txt?LANG=EN";

fn cache_path() -> PathBuf {
    std::env::temp_dir().join("wiivci-wiitdb-en.txt")
}

/// Parse GameTDB's `GAMEID = Title Name` flat format and return the title for `id`,
/// matched case-insensitively.
fn parse_wiitdb(text: &str, id: &str) -> Option<String> {
    for line in text.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let mut parts = line.splitn(2, '=');
        let key = parts.next()?.trim();
        let value = parts.next()?.trim();
        if key.eq_ignore_ascii_case(id) {
            return Some(value.to_string());
        }
    }
    None
}

/// Fetch the wiitdb.txt contents, using a cached copy in the system temp dir if present,
/// otherwise downloading and caching it. Returns `None` on any network failure.
fn fetch_wiitdb_text() -> Option<String> {
    let path = cache_path();
    if let Ok(text) = std::fs::read_to_string(&path) {
        if !text.is_empty() {
            return Some(text);
        }
    }

    let response = match reqwest::blocking::get(WIITDB_URL) {
        Ok(resp) => resp,
        Err(e) => {
            log::warn!("failed to reach gametdb.com: {e}");
            return None;
        }
    };

    let response = match response.error_for_status() {
        Ok(resp) => resp,
        Err(e) => {
            log::warn!("wiitdb request failed: {e}");
            return None;
        }
    };

    let text = match response.text() {
        Ok(t) => t,
        Err(e) => {
            log::warn!("failed to read wiitdb response body: {e}");
            return None;
        }
    };

    if let Err(e) = std::fs::write(&path, &text) {
        log::warn!("failed to cache wiitdb to {}: {e}", path.display());
    }

    Some(text)
}

/// Look up the English title for a 6-character Wii game ID (e.g. `"RSPE01"`) in GameTDB.
///
/// This is best-effort: any network failure yields `Ok(None)` rather than an error.
pub fn lookup_title(game_id6: &str) -> Result<Option<String>> {
    let Some(text) = fetch_wiitdb_text() else {
        return Ok(None);
    };
    Ok(parse_wiitdb(&text, game_id6))
}

#[cfg(test)]
mod tests {
    use super::*;

    const SAMPLE: &str = "\
# comment line
AGSE01 = Donkey Kong Country Returns
RSPE01 = Rhythm Heaven Fever
SOUP01 = Super Mario Galaxy 2
";

    #[test]
    fn finds_exact_match() {
        assert_eq!(
            parse_wiitdb(SAMPLE, "RSPE01"),
            Some("Rhythm Heaven Fever".to_string())
        );
    }

    #[test]
    fn matches_case_insensitively() {
        assert_eq!(
            parse_wiitdb(SAMPLE, "rspe01"),
            Some("Rhythm Heaven Fever".to_string())
        );
    }

    #[test]
    fn returns_none_when_missing() {
        assert_eq!(parse_wiitdb(SAMPLE, "ZZZZ99"), None);
    }

    #[test]
    fn skips_comments_and_blank_lines() {
        assert_eq!(
            parse_wiitdb(SAMPLE, "SOUP01"),
            Some("Super Mario Galaxy 2".to_string())
        );
    }
}
