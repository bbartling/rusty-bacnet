use super::*;

/// Each Annex A set with its Clause 20.2.9 code and its Annex A label.
const EXPECTED: [(CharacterSet, u8, &str); 6] = [
    (CharacterSet::Utf8, 0, "ISO 10646 (UTF-8)"),
    (CharacterSet::IbmMicrosoftDbcs, 1, "IBM/Microsoft DBCS"),
    (CharacterSet::JisX0208, 2, "JIS X 0208"),
    (CharacterSet::Ucs4, 3, "ISO 10646 (UCS-4)"),
    (CharacterSet::Ucs2, 4, "ISO 10646 (UCS-2)"),
    (CharacterSet::Iso8859_1, 5, "ISO 8859-1"),
];

fn all_sets_pics() -> Pics {
    let pics_config = PicsConfig {
        character_sets: CharacterSet::ALL.to_vec(),
        ..PicsConfig::default()
    };
    generate_pics(
        &ObjectDatabase::new(),
        &ServerConfig::default(),
        &pics_config,
    )
}

/// The body of the section that starts at `heading`, up to the next blank line.
fn section<'a>(doc: &'a str, heading: &str) -> &'a str {
    let start = doc.find(heading).expect("section heading") + heading.len();
    let body = &doc[start..];
    &body[..body.find("\n\n").map_or(body.len(), |end| end + 1)]
}

#[test]
fn all_lists_every_annex_a_set_once_with_its_encoding_code() {
    assert_eq!(CharacterSet::ALL, EXPECTED.map(|(set, _, _)| set));
    assert_eq!(
        CharacterSet::ALL.map(CharacterSet::code),
        [
            charset::UTF8,
            charset::IBM_MICROSOFT_DBCS,
            charset::JIS_X_0208,
            charset::UCS4,
            charset::UCS2,
            charset::ISO_8859_1,
        ]
    );
    for (set, code, label) in EXPECTED {
        assert_eq!(set.code(), code, "{set:?}");
        assert_eq!(set.to_string(), label, "{set:?}");
    }
}

#[test]
fn text_output_renders_every_character_set_label() {
    let text = all_sets_pics().generate_text();
    let expected: String = EXPECTED
        .iter()
        .map(|(_, _, label)| format!("  {label}\n"))
        .collect();
    assert_eq!(
        section(&text, "--- Character Sets Supported ---\n"),
        expected
    );
}

#[test]
fn markdown_output_renders_every_character_set_label() {
    let markdown = all_sets_pics().generate_markdown();
    let expected: String = EXPECTED
        .iter()
        .map(|(_, _, label)| format!("- {label}\n"))
        .collect();
    assert_eq!(
        section(&markdown, "## Character Sets Supported\n\n"),
        expected
    );
}
