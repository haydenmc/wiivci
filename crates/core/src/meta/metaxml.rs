//! Patches a base Wii U `meta/meta.xml` template with per-game identifiers and names.

use quick_xml::events::{BytesText, Event};
use quick_xml::reader::Reader;
use quick_xml::writer::Writer;

use super::titleid::TitleIds;
use crate::error::{Error, Result};

/// The twelve language suffixes used by `longname_XX`/`shortname_XX`/`publisher_XX`.
const LANGS: [&str; 12] = [
    "ja", "en", "fr", "de", "it", "es", "zhs", "ko", "nl", "pt", "ru", "zht",
];

/// Per-game values used to patch a base `meta.xml`.
pub struct MetaOptions<'a> {
    /// Derived title identifiers for the injected game.
    pub ids: &'a TitleIds,
    /// Long display name, applied to every `longname_XX` element. May contain a newline
    /// for two-line names.
    pub long_name: &'a str,
    /// Short display name, applied to every `shortname_XX` element.
    pub short_name: &'a str,
    /// Publisher name, applied to every `publisher_XX` element.
    pub publisher: &'a str,
    /// Region flags, e.g. `2` for USA.
    pub region: u32,
    /// Whether the Wii U GamePad screen is used.
    pub drc_use: bool,
}

fn replacement_for(name: &str, opts: &MetaOptions) -> Option<String> {
    match name {
        "product_code" => Some(opts.ids.product_code.clone()),
        "title_id" => Some(format!("{:016X}", opts.ids.title_id)),
        "group_id" => Some(format!("{:08X}", opts.ids.group_id)),
        "region" => Some(format!("{:08X}", opts.region)),
        "drc_use" => Some(if opts.drc_use { "1" } else { "0" }.to_string()),
        "reserved_flag2" => Some(format!("{:08X}", opts.ids.reserved_flag2)),
        _ => {
            for lang in LANGS {
                if name == format!("longname_{lang}") {
                    return Some(opts.long_name.to_string());
                }
                if name == format!("shortname_{lang}") {
                    return Some(opts.short_name.to_string());
                }
                if name == format!("publisher_{lang}") {
                    return Some(opts.publisher.to_string());
                }
            }
            None
        }
    }
}

fn xml_read_err(e: quick_xml::Error) -> Error {
    Error::Other(anyhow::anyhow!("meta.xml parse error: {e}"))
}

fn xml_write_err(e: std::io::Error) -> Error {
    Error::Other(anyhow::anyhow!("meta.xml write error: {e}"))
}

/// Patch `base_meta_xml` with `opts`, replacing only the text content of the identifier,
/// region, DRC-use and localized name/publisher elements. Every other byte — attributes,
/// whitespace, the XML declaration and the BOM — is preserved as-is.
pub fn patch(base_meta_xml: &str, opts: &MetaOptions) -> Result<String> {
    let (has_bom, body) = match base_meta_xml.strip_prefix('\u{FEFF}') {
        Some(rest) => (true, rest),
        None => (false, base_meta_xml),
    };

    let mut reader = Reader::from_str(body);
    let mut writer = Writer::new(Vec::new());

    loop {
        match reader.read_event().map_err(xml_read_err)? {
            Event::Eof => break,
            Event::Start(start) => {
                let local = String::from_utf8_lossy(start.name().as_ref()).into_owned();
                let replacement = replacement_for(&local, opts);

                writer
                    .write_event(Event::Start(start))
                    .map_err(xml_write_err)?;

                if let Some(text) = replacement {
                    let end_event = match reader.read_event().map_err(xml_read_err)? {
                        Event::Text(_) => reader.read_event().map_err(xml_read_err)?,
                        other => other,
                    };

                    if !text.is_empty() {
                        writer
                            .write_event(Event::Text(BytesText::new(&text)))
                            .map_err(xml_write_err)?;
                    }
                    writer.write_event(end_event).map_err(xml_write_err)?;
                }
            }
            other => writer.write_event(other).map_err(xml_write_err)?,
        }
    }

    let out_bytes = writer.into_inner();
    let mut out = String::from_utf8(out_bytes)
        .map_err(|e| Error::Other(anyhow::anyhow!("patched meta.xml is not valid utf-8: {e}")))?;
    if has_bom {
        out.insert(0, '\u{FEFF}');
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::meta::titleid::derive;
    use std::path::Path;

    fn base_meta_xml() -> Option<String> {
        let path = Path::new(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../.dev/base/meta/meta.xml"
        ));
        std::fs::read_to_string(path).ok()
    }

    #[test]
    fn patches_identifiers_and_names() {
        let Some(base) = base_meta_xml() else {
            eprintln!("skipping: base meta.xml not found");
            return;
        };

        let ids = derive(*b"RSPE");
        let opts = MetaOptions {
            ids: &ids,
            long_name: "Rhythm Heaven Fever\nTest",
            short_name: "Rhythm Heaven",
            publisher: "Nintendo",
            region: 2,
            drc_use: true,
        };

        let patched = patch(&base, &opts).expect("patch succeeds");

        assert!(patched.starts_with('\u{FEFF}'));
        assert!(patched
            .contains("<title_id type=\"hexBinary\" length=\"8\">0005000252535045</title_id>"));
        assert!(patched.contains("<group_id type=\"hexBinary\" length=\"4\">52535045</group_id>"));
        assert!(patched
            .contains("<product_code type=\"string\" length=\"32\">WUP-N-RSPE</product_code>"));
        assert!(patched.contains("<region type=\"hexBinary\" length=\"4\">00000002</region>"));
        assert!(patched.contains("<drc_use type=\"unsignedInt\" length=\"4\">1</drc_use>"));
        assert!(patched
            .contains("<reserved_flag2 type=\"hexBinary\" length=\"4\">52535045</reserved_flag2>"));

        for lang in LANGS {
            assert!(patched.contains(&format!(
                "<longname_{lang} type=\"string\" length=\"512\">Rhythm Heaven Fever\nTest</longname_{lang}>"
            )));
            assert!(patched.contains(&format!(
                "<shortname_{lang} type=\"string\" length=\"256\">Rhythm Heaven</shortname_{lang}>"
            )));
            assert!(patched.contains(&format!(
                "<publisher_{lang} type=\"string\" length=\"256\">Nintendo</publisher_{lang}>"
            )));
        }

        // Untouched fields survive unchanged.
        assert!(patched.contains(
            "<olv_accesskey type=\"unsignedInt\" length=\"4\">1615642778</olv_accesskey>"
        ));
        assert!(patched.contains("<pc_esrb type=\"unsignedInt\" length=\"4\">6</pc_esrb>"));
        assert!(patched
            .contains("<reserved_flag0 type=\"hexBinary\" length=\"4\">00010001</reserved_flag0>"));
    }

    #[test]
    fn preserves_untouched_bytes_outside_targets() {
        let Some(base) = base_meta_xml() else {
            eprintln!("skipping: base meta.xml not found");
            return;
        };

        let ids = derive(*b"RSPE");
        let opts = MetaOptions {
            ids: &ids,
            long_name: "X",
            short_name: "Y",
            publisher: "Z",
            region: 2,
            drc_use: false,
        };

        let patched = patch(&base, &opts).expect("patch succeeds");
        // The overall structure (line count) must be unchanged.
        assert_eq!(patched.lines().count(), base.lines().count());
    }
}
