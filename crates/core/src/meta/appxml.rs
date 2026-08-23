//! Generation of the Wii U `code/app.xml` manifest for an injected title.

use super::titleid::TitleIds;

/// Generate the `code/app.xml` contents for a title, matching the base template byte-for-byte
/// except for the `title_id` and `group_id` element text.
pub fn generate(ids: &TitleIds) -> String {
    let lines = [
        "<?xml version=\"1.0\" encoding=\"utf-8\"?>".to_string(),
        "<app type=\"complex\" access=\"777\">".to_string(),
        "  <version type=\"unsignedInt\" length=\"4\">16</version>".to_string(),
        "  <os_version type=\"hexBinary\" length=\"8\">000500101000400A</os_version>".to_string(),
        format!(
            "  <title_id type=\"hexBinary\" length=\"8\">{:016X}</title_id>",
            ids.title_id
        ),
        "  <title_version type=\"hexBinary\" length=\"2\">0000</title_version>".to_string(),
        "  <sdk_version type=\"unsignedInt\" length=\"4\">21204</sdk_version>".to_string(),
        "  <app_type type=\"hexBinary\" length=\"4\">8000002E</app_type>".to_string(),
        format!(
            "  <group_id type=\"hexBinary\" length=\"4\">{:08X}</group_id>",
            ids.group_id
        ),
        "  <os_mask type=\"hexBinary\" length=\"32\">0000000000000000000000000000000000000000000000000000000000000000</os_mask>".to_string(),
        "  <common_id type=\"hexBinary\" length=\"8\">0000000000000000</common_id>".to_string(),
        "</app>".to_string(),
    ];

    format!("\u{FEFF}{}", lines.join("\n"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::meta::titleid::derive;

    #[test]
    fn generates_title_and_group_id() {
        let ids = derive(*b"RSPE");
        let xml = generate(&ids);

        assert!(xml.starts_with('\u{FEFF}'));
        assert!(
            xml.contains("<title_id type=\"hexBinary\" length=\"8\">0005000252535045</title_id>")
        );
        assert!(xml.contains("<group_id type=\"hexBinary\" length=\"4\">52535045</group_id>"));
    }

    #[test]
    fn matches_reference_byte_length() {
        let ids = derive(*b"RSPE");
        let xml = generate(&ids);
        assert_eq!(xml.len(), 712);
    }

    #[test]
    fn parses_as_xml() {
        let ids = derive(*b"RSPE");
        let xml = generate(&ids);
        let body = xml.strip_prefix('\u{FEFF}').unwrap();

        let mut reader = quick_xml::reader::Reader::from_str(body);
        let mut saw_end = false;
        loop {
            match reader.read_event().expect("valid xml") {
                quick_xml::events::Event::Eof => break,
                quick_xml::events::Event::End(e) if e.name().as_ref() == b"app" => {
                    saw_end = true;
                }
                _ => {}
            }
        }
        assert!(saw_end);
    }
}
