//! Structural checks on one ledger row: status, test membership, code anchors
//! and gaps (#1209).
//!
//! These replace tests that pinned phrases of the row's prose, so a row can be
//! reworded freely while its status cannot rise and its evidence cannot be
//! dropped silently. `scripts/generate-conformance-docs.py --check` (run by
//! `generated_support_docs_match_generator_check`) resolves every anchor and
//! runs the row style check.
use super::*;

/// A row's one-sentence summary: `summary`, or `requirement_summary` on a row
/// the lean-schema conversion (#1208) has not reached yet.
pub(super) fn summary(row: &Value) -> &str {
    row.get("summary")
        .or_else(|| row.get("requirement_summary"))
        .and_then(Value::as_str)
        .unwrap_or_default()
}

/// A row's open-work entries; a row without `gaps` has none.
pub(super) fn gaps(row: &Value) -> Vec<&str> {
    match row.get("gaps") {
        None => Vec::new(),
        Some(Value::Array(entries)) => entries
            .iter()
            .map(|entry| {
                entry
                    .as_str()
                    .unwrap_or_else(|| panic!("{} gaps entry {entry} is not a string", row["id"]))
            })
            .collect(),
        Some(other) => panic!("{} gaps must be an array, not {other}", row["id"]),
    }
}

/// Whether the style checker still reads `id` in the old schema, through
/// `scripts/ledger_style_pending.txt`.
fn style_pending(id: &str) -> bool {
    read_repo_file("scripts/ledger_style_pending.txt")
        .lines()
        .map(|line| line.split('#').next().unwrap_or_default().trim())
        .any(|line| line == id)
}

/// The row keeps exactly `status`: new evidence never promotes it silently.
pub(super) fn assert_status(row: &Value, status: &str) {
    assert_eq!(row["status"], status, "{} status changed", row["id"]);
}

/// Every entry of `anchors` is still listed in the row's `field`.
pub(super) fn assert_listed(row: &Value, field: &str, anchors: &[&str]) {
    let listed = row[field]
        .as_array()
        .unwrap_or_else(|| panic!("{} {field} should be an array", row["id"]));
    for anchor in anchors {
        assert!(
            listed.iter().any(|entry| entry == anchor),
            "{} {field} dropped {anchor}",
            row["id"]
        );
    }
}

/// At least `min` of the row's positive and negative tests have `needle` in
/// their anchor, so a test family cannot shrink unnoticed.
pub(super) fn assert_test_family(row: &Value, needle: &str, min: usize) {
    let count = ["positive_tests", "negative_tests"]
        .iter()
        .flat_map(|field| row[*field].as_array().into_iter().flatten())
        .filter(|anchor| anchor.as_str().is_some_and(|a| a.contains(needle)))
        .count();
    assert!(
        count >= min,
        "{} lists {count} `{needle}` tests, fewer than {min}",
        row["id"]
    );
}

/// A row whose status is partial keeps its open work as gaps once it is in the
/// lean schema; a pending row is still in the old schema and is skipped.
pub(super) fn assert_open_work_recorded(row: &Value) {
    let id = row["id"].as_str().expect("row id should be a string");
    if !style_pending(id) {
        assert!(
            !gaps(row).is_empty(),
            "{id} has status {} but no gaps",
            row["status"]
        );
    }
}

#[test]
fn summary_falls_back_to_requirement_summary() {
    assert_eq!(summary(&json!({"summary": "New."})), "New.");
    assert_eq!(summary(&json!({"requirement_summary": "Old."})), "Old.");
    let both = json!({"summary": "New.", "requirement_summary": "Old."});
    assert_eq!(summary(&both), "New.");
    assert_eq!(summary(&json!({})), "");
}

#[test]
fn missing_gaps_read_as_empty() {
    assert!(gaps(&json!({"id": "X"})).is_empty());
    assert_eq!(
        gaps(&json!({"id": "X", "gaps": ["#1: open."]})),
        ["#1: open."]
    );
}

#[test]
#[should_panic(expected = "has status \"in-progress\" but no gaps")]
fn open_work_check_rejects_a_lean_partial_row_without_gaps() {
    assert_open_work_recorded(&json!({"id": "BACNET-TEST-NOT-PENDING", "status": "in-progress"}));
}

#[test]
#[should_panic(expected = "dropped crates/x.rs::t")]
fn listed_check_rejects_a_dropped_anchor() {
    let row = json!({"id": "X", "positive_tests": ["crates/y.rs::t"]});
    assert_listed(&row, "positive_tests", &["crates/x.rs::t"]);
}

#[test]
#[should_panic(expected = "fewer than 2")]
fn test_family_check_rejects_a_shrunken_family() {
    let row = json!({"id": "X", "positive_tests": ["a_family::t"], "negative_tests": []});
    assert_test_family(&row, "family", 2);
}
