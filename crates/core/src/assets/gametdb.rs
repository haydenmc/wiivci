//! Best-effort game title lookup against GameTDB's flat `wiitdb.txt` database.

use std::path::PathBuf;
use std::time::Duration;

use crate::error::Result;

const WIITDB_URL: &str = "https://www.gametdb.com/wiitdb.txt?LANG=EN";
const CACHE_FILE_NAME: &str = "wiitdb-en.txt";
const FETCH_TIMEOUT: Duration = Duration::from_secs(30);

/// A per-user subdirectory name under the system temp dir, so the cache file doesn't live at a
/// fixed, world-guessable path (symlink/pre-creation hazard on multi-user hosts).
fn cache_dir_name() -> String {
    let user = std::env::var("USER")
        .or_else(|_| std::env::var("USERNAME"))
        .unwrap_or_else(|_| "shared".to_string());
    let sanitized: String = user
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || c == '-' || c == '_' {
                c
            } else {
                '_'
            }
        })
        .collect();
    format!("wiivci-{sanitized}")
}

/// The per-user cache directory, created (and, on unix, locked down to owner-only) on demand.
/// Returns `None` if the path exists but isn't a plain directory (e.g. a pre-planted symlink) or
/// if it can't be created — callers should treat that as "caching unavailable", not an error.
fn cache_dir() -> Option<PathBuf> {
    let dir = std::env::temp_dir().join(cache_dir_name());
    match std::fs::symlink_metadata(&dir) {
        Ok(meta) => {
            if !meta.is_dir() {
                log::warn!(
                    "cache dir {} exists but isn't a plain directory; skipping cache",
                    dir.display()
                );
                return None;
            }
        }
        Err(_) => {
            if let Err(e) = std::fs::create_dir_all(&dir) {
                log::debug!("failed to create cache dir {}: {e}", dir.display());
                return None;
            }
        }
    }

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if let Ok(meta) = std::fs::metadata(&dir) {
            let mut perms = meta.permissions();
            perms.set_mode(0o700);
            let _ = std::fs::set_permissions(&dir, perms);
        }
    }

    Some(dir)
}

fn cache_path() -> Option<PathBuf> {
    cache_dir().map(|d| d.join(CACHE_FILE_NAME))
}

/// Heuristic check that `text` looks like real GameTDB `wiitdb.txt` content rather than an HTML
/// error page or an empty/partial write: it must contain at least one `XXXXXX = ...` style entry
/// line (a 6-character alphanumeric game id) and must not look like an HTML document.
fn looks_like_wiitdb(text: &str) -> bool {
    if text.trim().is_empty() {
        return false;
    }
    let head_lower: String = text
        .chars()
        .take(512)
        .collect::<String>()
        .to_ascii_lowercase();
    if head_lower.contains("<!doctype") || head_lower.contains("<html") {
        return false;
    }
    text.lines().any(|line| {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            return false;
        }
        let mut parts = line.splitn(2, '=');
        match (parts.next(), parts.next()) {
            (Some(key), Some(_value)) => {
                let key = key.trim();
                key.len() == 6 && key.chars().all(|c| c.is_ascii_alphanumeric())
            }
            _ => false,
        }
    })
}

/// Parse GameTDB's `GAMEID = Title Name` flat format and return the title for `id`,
/// matched case-insensitively. Lines that don't fit the `key = value` shape (a header, a
/// separator, a truncated tail line, ...) are skipped rather than aborting the whole parse.
fn parse_wiitdb(text: &str, id: &str) -> Option<String> {
    for line in text.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let mut parts = line.splitn(2, '=');
        let Some(key) = parts.next() else {
            log::debug!("skipping malformed wiitdb line: {line:?}");
            continue;
        };
        let Some(value) = parts.next() else {
            log::debug!("skipping malformed wiitdb line: {line:?}");
            continue;
        };
        let key = key.trim();
        let value = value.trim();
        if key.eq_ignore_ascii_case(id) {
            return Some(value.to_string());
        }
    }
    None
}

/// Fetch the wiitdb.txt contents, using a cached copy in the per-user temp dir if it's present
/// and looks valid, otherwise downloading and caching it. Returns `None` on any network failure
/// or if the downloaded content doesn't look like a real wiitdb.
fn fetch_wiitdb_text() -> Option<String> {
    let path = cache_path();

    if let Some(path) = &path {
        match std::fs::read_to_string(path) {
            Ok(text) if looks_like_wiitdb(&text) => return Some(text),
            Ok(_) => {
                log::debug!(
                    "cached wiitdb at {} doesn't look valid; refreshing",
                    path.display()
                );
                let _ = std::fs::remove_file(path);
            }
            Err(_) => {}
        }
    }

    let client = match reqwest::blocking::Client::builder()
        .timeout(FETCH_TIMEOUT)
        .build()
    {
        Ok(c) => c,
        Err(e) => {
            log::warn!("failed to build HTTP client: {e}");
            return None;
        }
    };

    let response = match client.get(WIITDB_URL).send() {
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

    if !looks_like_wiitdb(&text) {
        log::warn!("downloaded wiitdb from {WIITDB_URL} doesn't look valid; not using it");
        return None;
    }

    if let Some(path) = &path {
        // Write atomically: to a temp file in the same directory, then rename, so a partial
        // write (e.g. the process getting killed mid-write) can never be cached.
        if let Some(dir) = path.parent() {
            let tmp = dir.join(format!(".{CACHE_FILE_NAME}.{}.tmp", std::process::id()));
            match std::fs::write(&tmp, &text) {
                Ok(()) => {
                    if let Err(e) = std::fs::rename(&tmp, path) {
                        log::warn!("failed to finalize wiitdb cache at {}: {e}", path.display());
                        let _ = std::fs::remove_file(&tmp);
                    }
                }
                Err(e) => log::warn!("failed to write wiitdb cache temp file: {e}"),
            }
        }
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

    #[test]
    fn tolerates_header_line_without_equals() {
        // A leading header/title line with no `=` used to make `parts.next()?` return `None`
        // from the whole function via `?`, making every entry after it unfindable.
        let text = "\
wiitdb.txt - GameTDB flat title database
AGSE01 = Donkey Kong Country Returns
RSPE01 = Rhythm Heaven Fever
";
        assert_eq!(
            parse_wiitdb(text, "RSPE01"),
            Some("Rhythm Heaven Fever".to_string())
        );
    }

    #[test]
    fn tolerates_mid_file_garbage_line() {
        let text = "\
AGSE01 = Donkey Kong Country Returns
this is not a valid entry line at all
RSPE01 = Rhythm Heaven Fever
SOUP01 = Super Mario Galaxy 2
";
        assert_eq!(
            parse_wiitdb(text, "AGSE01"),
            Some("Donkey Kong Country Returns".to_string())
        );
        assert_eq!(
            parse_wiitdb(text, "RSPE01"),
            Some("Rhythm Heaven Fever".to_string())
        );
        assert_eq!(
            parse_wiitdb(text, "SOUP01"),
            Some("Super Mario Galaxy 2".to_string())
        );
    }

    #[test]
    fn tolerates_truncated_trailing_line() {
        let text = "\
AGSE01 = Donkey Kong Country Returns
RSPE01 = Rhythm Heaven Fever
SOUP0";
        assert_eq!(
            parse_wiitdb(text, "AGSE01"),
            Some("Donkey Kong Country Returns".to_string())
        );
        assert_eq!(
            parse_wiitdb(text, "RSPE01"),
            Some("Rhythm Heaven Fever".to_string())
        );
        assert_eq!(parse_wiitdb(text, "SOUP01"), None);
    }

    #[test]
    fn looks_like_wiitdb_accepts_real_text() {
        assert!(looks_like_wiitdb(SAMPLE));
    }

    #[test]
    fn looks_like_wiitdb_rejects_html_error_page() {
        assert!(!looks_like_wiitdb(
            "<!DOCTYPE html>\n<html><body>502 Bad Gateway</body></html>\n"
        ));
        assert!(!looks_like_wiitdb(
            "<html><head><title>Error</title></head></html>\n"
        ));
    }

    #[test]
    fn looks_like_wiitdb_rejects_empty() {
        assert!(!looks_like_wiitdb(""));
        assert!(!looks_like_wiitdb("   \n  \n"));
    }

    #[test]
    fn looks_like_wiitdb_rejects_text_with_no_entry_lines() {
        assert!(!looks_like_wiitdb("# just a comment\n\n"));
    }
}
