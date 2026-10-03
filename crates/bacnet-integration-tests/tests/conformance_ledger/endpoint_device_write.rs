use super::*;

#[test]
fn endpoint_device_write_claim_stays_within_executed_subset() {
    let data = ledger();
    let rows = rows_by_id(&data);
    let row = rows
        .get("BACNET-15-ENDPOINT-DEVICE-WRITE")
        .expect("endpoint write evidence row");
    assert_status(row, "in-progress");
    assert_listed(
        row,
        "code_anchors",
        &[
            "crates/bacnet-endpoint/src/device_writes.rs",
            "crates/bacnet-server/src/server/requests/endpoint_responder.rs",
        ],
    );
    // The opt-in default, the Description and recipient scope, the
    // advertised profile and the WPM refusal each keep their test.
    assert_listed(row, "positive_tests", &[
        "crates/bacnet-endpoint/src/device_write_tests.rs::device_write_profile_matches_execution_with_and_without_identity",
        "crates/bacnet-server/src/handlers/tests/device_description_writes.rs::device_description_full_handler_null_is_noop_and_priority_range_is_typed",
        "crates/bacnet-server/src/handlers/tests/audit_recipient_writes.rs::recipient_null_relinquishment_is_noop_and_wpm_continues",
    ]);
    assert_listed(row, "negative_tests", &[
        "crates/bacnet-server/src/server/requests/endpoint_device_write_tests.rs::endpoint_device_write_default_refusal_and_panic_never_mutate",
        "crates/bacnet-server/src/server/requests/endpoint_device_write_tests.rs::endpoint_device_write_group_silence_segment_abort_and_wpm_reject",
        "crates/bacnet-endpoint/src/device_write_tests.rs::device_write_rejects_device_shaped_custom_object_without_authority",
    ]);
    assert_open_work_recorded(row);
}
