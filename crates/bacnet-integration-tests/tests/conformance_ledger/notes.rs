//! Row notes: one string, or an array of entries read as one text.
use super::*;

/// A row's `notes` as one text. The ledger keeps notes either as one string
/// or as an array with one entry per topic, so PRs that edit different
/// entries merge cleanly (#1176); the entries joined with single spaces are
/// the text, as `scripts/ledger_notes_split.py` and the generated docs read it.
pub(super) fn notes_text(row: &Value) -> String {
    match &row["notes"] {
        Value::String(text) => text.clone(),
        Value::Array(entries) => entries
            .iter()
            .map(|entry| {
                entry
                    .as_str()
                    .unwrap_or_else(|| panic!("{} notes entry {entry} is not a string", row["id"]))
            })
            .collect::<Vec<_>>()
            .join(" "),
        other => panic!(
            "{} notes must be a string or an array of strings, not {other}",
            row["id"]
        ),
    }
}

#[test]
fn ledger_notes_are_one_string_or_trimmed_entries() {
    let data = ledger();
    for row in data["rows"].as_array().expect("rows should be an array") {
        assert!(!notes_text(row).is_empty(), "{} has no notes", row["id"]);
        for entry in row["notes"].as_array().into_iter().flatten() {
            let entry = entry.as_str().unwrap_or_default();
            assert!(
                !entry.is_empty() && entry.trim() == entry,
                "{} notes entries must be non-empty without outer whitespace: {entry:?}",
                row["id"]
            );
        }
    }
}

#[test]
fn notes_text_joins_entries_with_single_spaces() {
    let one = json!({"id": "X", "notes": "First topic. Second topic."});
    let split = json!({"id": "X", "notes": ["First topic.", "Second topic."]});
    assert_eq!(notes_text(&split), "First topic. Second topic.");
    assert_eq!(notes_text(&one), notes_text(&split));
}

#[test]
#[should_panic(expected = "notes must be a string or an array of strings")]
fn notes_text_rejects_other_shapes() {
    notes_text(&json!({"id": "X", "notes": {"text": "First topic."}}));
}
