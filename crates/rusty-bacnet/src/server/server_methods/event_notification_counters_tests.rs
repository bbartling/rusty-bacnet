use super::*;

use std::collections::BTreeMap;

use super::super::cov_counters::tests::{stub_class_members, STUB};

#[test]
fn every_event_notification_counter_reaches_python_under_its_rust_name() {
    // A literal naming every field, each value distinct, so a field read into
    // the wrong key shows up.
    let counters = EventNotificationCounters {
        notification_class_missing: 1,
        recipient_list_unavailable: 2,
        recipient_list_invalid: 3,
        recipient_list_too_long: 4,
        confirmed_no_invoke_id: 5,
        confirmed_rejected: 6,
        confirmed_unanswered: 7,
    };
    assert_eq!(
        event_notification_counter_entries(counters),
        HashMap::from([
            ("notification_class_missing", 1),
            ("recipient_list_unavailable", 2),
            ("recipient_list_invalid", 3),
            ("recipient_list_too_long", 4),
            ("confirmed_no_invoke_id", 5),
            ("confirmed_rejected", 6),
            ("confirmed_unanswered", 7),
        ])
    );
}

#[test]
fn stub_typed_dict_lists_every_event_notification_counter_as_int() {
    let expected: BTreeMap<_, _> =
        event_notification_counter_entries(EventNotificationCounters::default())
            .into_keys()
            .map(|name| (name, "int"))
            .collect();
    assert_eq!(
        stub_class_members("class EventNotificationCounters(TypedDict):"),
        expected
    );
    assert!(
        STUB.contains(
            "\n    def event_notification_counters(self) -> Awaitable[EventNotificationCounters]:\n"
        ),
        "BACnetServer.event_notification_counters missing from rusty_bacnet.pyi"
    );
}
