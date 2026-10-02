use super::*;

use std::collections::BTreeMap;

const STUB: &str = include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/rusty_bacnet.pyi"));

/// A literal naming every field, so a new `CovCounters` field stops this test
/// compiling as well as the binding. Each value is distinct, so a field read
/// into the wrong key shows up.
fn distinct_counters() -> CovCounters {
    CovCounters {
        subscriptions_active: 1,
        subscriptions_created: 2,
        subscriptions_rejected_quota: 3,
        subscriptions_rejected_capacity: 4,
        subscriptions_rejected_indefinite: 5,
        subscriptions_cancelled: 6,
        subscriptions_purged: 7,
        notifications_sent: 8,
        notifications_confirmed: 9,
        notifications_unconfirmed: 10,
        notification_bytes_sent: 11,
        notifications_throttled_fanout: 12,
        notifications_throttled_peer: 13,
        timed_changes_dropped: 14,
        untimed_references_oversized: 15,
    }
}

#[test]
fn every_cov_counter_reaches_python_under_its_rust_name() {
    assert_eq!(
        cov_counter_entries(distinct_counters()),
        HashMap::from([
            ("subscriptions_active", 1),
            ("subscriptions_created", 2),
            ("subscriptions_rejected_quota", 3),
            ("subscriptions_rejected_capacity", 4),
            ("subscriptions_rejected_indefinite", 5),
            ("subscriptions_cancelled", 6),
            ("subscriptions_purged", 7),
            ("notifications_sent", 8),
            ("notifications_confirmed", 9),
            ("notifications_unconfirmed", 10),
            ("notification_bytes_sent", 11),
            ("notifications_throttled_fanout", 12),
            ("notifications_throttled_peer", 13),
            ("timed_changes_dropped", 14),
            ("untimed_references_oversized", 15),
        ])
    );
}

/// The `name: annotation` members of a top-level stub class, read up to the
/// first line that is neither indented nor blank.
fn stub_class_members(class_header: &str) -> BTreeMap<&'static str, &'static str> {
    let (_, body) = STUB
        .split_once(&format!("\n{class_header}\n"))
        .unwrap_or_else(|| panic!("`{class_header}` missing from rusty_bacnet.pyi"));
    let is_identifier = |text: &str| {
        !text.is_empty() && text.chars().all(|c| c.is_ascii_alphanumeric() || c == '_')
    };
    body.lines()
        .take_while(|line| line.is_empty() || line.starts_with(' '))
        .filter_map(|line| line.trim().split_once(": "))
        .filter(|(name, annotation)| is_identifier(name) && is_identifier(annotation))
        .collect()
}

#[test]
fn stub_typed_dict_lists_every_cov_counter_as_int() {
    let expected: BTreeMap<_, _> = cov_counter_entries(CovCounters::default())
        .into_keys()
        .map(|name| (name, "int"))
        .collect();
    assert_eq!(
        stub_class_members("class CovCounters(TypedDict):"),
        expected
    );
    assert!(
        STUB.contains("\n    def cov_counters(self) -> Awaitable[CovCounters]:\n"),
        "BACnetServer.cov_counters missing from rusty_bacnet.pyi"
    );
}
