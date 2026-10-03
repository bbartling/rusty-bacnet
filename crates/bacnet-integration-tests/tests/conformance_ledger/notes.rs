//! Row notes: an array with one topic per entry (#1176), so PRs that add
//! different entries to one row merge cleanly. A lean row may have none.
use super::*;

#[test]
fn ledger_notes_are_arrays_of_trimmed_entries() {
    let data = ledger();
    for row in data["rows"].as_array().expect("rows should be an array") {
        let entries = row["notes"]
            .as_array()
            .unwrap_or_else(|| panic!("{} notes must be an array", row["id"]));
        for entry in entries {
            let entry = entry.as_str().unwrap_or_default();
            assert!(
                !entry.is_empty() && entry.trim() == entry,
                "{} notes entries must be non-empty strings without outer whitespace: {entry:?}",
                row["id"]
            );
        }
    }
}
