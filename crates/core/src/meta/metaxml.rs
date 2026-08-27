//! Patches a base Wii U `meta/meta.xml` template with per-game identifiers and names.

use quick_xml::escape::escape;
use quick_xml::events::{BytesStart, BytesText, Event};
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

/// Reads a named attribute of `start` as a string, if present. A read/decode failure on the
/// attribute itself (not on unrelated parts of the document) is propagated as an error.
fn read_attr(start: &BytesStart, name: &str) -> Result<Option<String>> {
    let attr = start
        .try_get_attribute(name)
        .map_err(|e| xml_read_err(e.into()))?;
    let Some(attr) = attr else {
        return Ok(None);
    };
    let value = attr.unescape_value().map_err(xml_read_err)?;
    Ok(Some(value.into_owned()))
}

/// Reads the `length="N"` attribute of `start`, if present, as a numeric capacity. A malformed
/// (non-numeric) `length` attribute is treated as "no declared capacity" rather than an error,
/// since it isn't this function's job to validate the base template.
fn declared_length(start: &BytesStart) -> Result<Option<usize>> {
    Ok(read_attr(start, "length")?.and_then(|v| v.parse::<usize>().ok()))
}

/// Errors if `field`'s replacement `text` would violate the capacity declared by `start`'s
/// `length` attribute. `meta.xml` gives that attribute two different units depending on
/// `type`:
///
/// - `type="string"`: `length` is the max **byte** count of the (XML-escaped) text content —
///   e.g. `<longname_en type="string" length="512">`.
/// - `type="hexBinary"`: `length` is the **binary** byte count the hex text decodes to, so the
///   text itself is expected to be exactly `2 * length` hex characters — e.g.
///   `<title_id type="hexBinary" length="8">` holds 16 hex chars.
///
/// Any other (or missing) `type` has no length semantics this function understands, so no check
/// is applied — the base's own values for those fields are trusted as-is.
fn check_length(field: &str, start: &BytesStart, text: &str) -> Result<()> {
    let Some(limit) = declared_length(start)? else {
        return Ok(());
    };
    match read_attr(start, "type")?.as_deref() {
        Some("string") => {
            let escaped_len = escape(text).len();
            if escaped_len > limit {
                return Err(Error::FormatLimit(format!(
                    "meta.xml field `{field}` value is {escaped_len} bytes (escaped), exceeding \
                     its declared length={limit}"
                )));
            }
        }
        Some("hexBinary") => {
            if let Some(expected_chars) = limit.checked_mul(2) {
                if text.len() != expected_chars {
                    return Err(Error::FormatLimit(format!(
                        "meta.xml field `{field}` value is {} hex chars, but its declared \
                         length={limit} expects exactly {expected_chars}",
                        text.len()
                    )));
                }
            }
        }
        _ => {}
    }
    Ok(())
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

                if let Some(text) = &replacement {
                    check_length(&local, &start, text)?;
                }

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
            // A self-closing target element (e.g. `<publisher_ja/>`) has no Start/Text/End
            // triplet to rewrite the text of, so it must be expanded into one instead of
            // falling through to the generic passthrough arm — otherwise the base's (absent)
            // value would silently survive the patch.
            Event::Empty(start) => {
                let local = String::from_utf8_lossy(start.name().as_ref()).into_owned();
                match replacement_for(&local, opts) {
                    Some(text) => {
                        check_length(&local, &start, &text)?;
                        let end = start.to_end().into_owned();

                        writer
                            .write_event(Event::Start(start))
                            .map_err(xml_write_err)?;
                        if !text.is_empty() {
                            writer
                                .write_event(Event::Text(BytesText::new(&text)))
                                .map_err(xml_write_err)?;
                        }
                        writer.write_event(Event::End(end)).map_err(xml_write_err)?;
                    }
                    None => writer
                        .write_event(Event::Empty(start))
                        .map_err(xml_write_err)?,
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
    use crate::meta::titleid::{derive, TitleIds};
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
            eprintln!(
                "skipping patches_identifiers_and_names: .dev/base/meta/meta.xml not present"
            );
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
            eprintln!(
                "skipping preserves_untouched_bytes_outside_targets: .dev/base/meta/meta.xml not present"
            );
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

    // --- Hermetic tests below: a small self-contained meta.xml fixture, no `.dev/` fixture
    // needed. Covers the two bugs this module was patched for (silently-skipped self-closing
    // target elements, and unchecked `length=` overflow) plus the ordinary Start/End path.

    /// A minimal but representative meta.xml body: one `length="512"` longname in ordinary
    /// Start/End form (the shape every field takes in the real base title), one target field
    /// in self-closing form (the shape that used to be silently skipped), a `type="hexBinary"`
    /// field (where `length` counts decoded binary bytes, not text chars), and one untouched
    /// field that must survive byte-for-byte.
    const FIXTURE: &str = r#"<?xml version="1.0" encoding="utf-8"?>
<menu>
  <longname_en type="string" length="512">Base Long Name</longname_en>
  <shortname_en type="string" length="256"/>
  <publisher_en type="string" length="256">Base Publisher</publisher_en>
  <title_id type="hexBinary" length="8">0000000000000000</title_id>
  <untouched_field type="string" length="16">Keep Me</untouched_field>
</menu>
"#;

    fn fixture_ids() -> TitleIds {
        derive(*b"RSPE")
    }

    #[test]
    fn hermetic_normal_start_end_patch_and_untouched_field() {
        let ids = fixture_ids();
        let opts = MetaOptions {
            ids: &ids,
            long_name: "Rhythm Heaven Fever",
            short_name: "",
            publisher: "",
            region: 2,
            drc_use: false,
        };

        let patched = patch(FIXTURE, &opts).expect("patch succeeds");

        assert!(patched.contains(
            "<longname_en type=\"string\" length=\"512\">Rhythm Heaven Fever</longname_en>"
        ));
        // Untouched field survives byte-for-byte, including its surrounding whitespace line.
        assert!(patched.contains(
            "  <untouched_field type=\"string\" length=\"16\">Keep Me</untouched_field>\n"
        ));
    }

    #[test]
    fn hermetic_self_closing_target_element_is_expanded_and_patched() {
        let ids = fixture_ids();
        let opts = MetaOptions {
            ids: &ids,
            long_name: "",
            short_name: "Short",
            publisher: "",
            region: 2,
            drc_use: false,
        };

        let patched = patch(FIXTURE, &opts).expect("patch succeeds");

        // Was self-closing in the fixture; must come out as Start + text + End.
        assert!(
            patched.contains("<shortname_en type=\"string\" length=\"256\">Short</shortname_en>")
        );
        assert!(!patched.contains("<shortname_en type=\"string\" length=\"256\"/>"));
    }

    #[test]
    fn hermetic_hex_binary_length_is_binary_bytes_not_text_chars() {
        // `derive(*b"RSPE")` yields title_id 0x0005000252535045, i.e. 16 hex chars for the
        // fixture's `type="hexBinary" length="8"` (8 binary bytes == 16 hex chars). Regression
        // test for treating `length` as a string byte cap on a hexBinary field, which would
        // wrongly reject this valid, real-shaped value (16 chars > 8).
        let ids = fixture_ids();
        let opts = MetaOptions {
            ids: &ids,
            long_name: "",
            short_name: "",
            publisher: "",
            region: 2,
            drc_use: false,
        };

        let patched = patch(FIXTURE, &opts).expect("valid hexBinary value must be accepted");
        assert!(patched
            .contains("<title_id type=\"hexBinary\" length=\"8\">0005000252535045</title_id>"));
    }

    #[test]
    fn hermetic_over_length_value_errors_and_names_the_field() {
        let ids = fixture_ids();
        let long_name = "A".repeat(513); // one byte over the fixture's length="512"
        let opts = MetaOptions {
            ids: &ids,
            long_name: &long_name,
            short_name: "",
            publisher: "",
            region: 2,
            drc_use: false,
        };

        let err = patch(FIXTURE, &opts).expect_err("over-length value must be rejected");
        let message = err.to_string();
        assert!(
            message.contains("longname_en"),
            "error should name the field, got: {message}"
        );
        assert!(
            message.contains("512"),
            "error should mention the declared length, got: {message}"
        );
    }

    #[test]
    fn hermetic_value_exactly_at_length_limit_passes() {
        let ids = fixture_ids();
        let long_name = "A".repeat(512); // exactly the fixture's length="512"
        let opts = MetaOptions {
            ids: &ids,
            long_name: &long_name,
            short_name: "",
            publisher: "",
            region: 2,
            drc_use: false,
        };

        let patched = patch(FIXTURE, &opts).expect("value at the exact limit must be accepted");
        assert!(patched.contains(&format!(
            "<longname_en type=\"string\" length=\"512\">{long_name}</longname_en>"
        )));
    }
}
