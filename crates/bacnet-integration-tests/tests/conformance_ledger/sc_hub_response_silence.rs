//! Bind the narrow accepting-hub supplement to actual tests, not a promotion.
use super::*;

const ROW: &str = "BACNET-AB-SC-CONNECTION-STATE";
const STATUS: &str = "implementation-present-needs-state-machine-audit";

#[test]
fn node_resolution_capability_evidence_keeps_live_policy_and_uri_knowledge_distinct() {
    let data = ledger();
    let row = rows_by_id(&data)[ROW];
    assert_status(row, STATUS);
    assert_listed(row, "positive_tests", &[
        "crates/bacnet-transport/src/sc/address_resolution_capability_tests.rs::live_listener_ack_preserves_empty_and_known_uris_ids_and_addresses",
    ]);
    assert_listed(row, "negative_tests", &[
        "crates/bacnet-transport/src/sc/address_resolution_tests.rs::absent_listener_refuses_regardless_of_configured_uris",
        "crates/bacnet-transport/src/sc/address_resolution_capability_tests.rs::capability_tracks_identity_application_intake_and_listener_lifecycle",
    ]);
    assert_open_work_recorded(row);
}

#[test]
fn hub_response_silence_has_scoped_policy_and_executable_anchors() {
    let data = ledger();
    let row = rows_by_id(&data)[ROW];
    assert_status(row, STATUS);
    assert_listed(
        row,
        "code_anchors",
        &[
            "crates/bacnet-transport/src/sc_hub/handler.rs",
            "crates/bacnet-transport/src/sc_hub/response_silence_tests.rs",
            "crates/bacnet-transport/src/sc_hub/response_silence_lifecycle_tests.rs",
        ],
    );
    assert_listed(row, "positive_tests", &[
        "crates/bacnet-transport/src/sc_hub/response_silence_tests.rs::unsolicited_response_matrix_preserves_lease_activity_and_probe_then_recovers",
        "crates/rusty-bacnet/tests/test_sc_hub_response_silence.py::HubResponseSilenceTests::test_unsolicited_responses_preserve_native_hub_and_registration",
    ]);
    assert_listed(row, "negative_tests", &[
        "crates/bacnet-transport/src/sc_hub/response_silence_tests.rs::unsolicited_connect_accept_is_silent_before_and_after_registration",
        "crates/bacnet-transport/src/sc_hub/response_silence_tests.rs::unsolicited_disconnect_ack_is_silent_before_and_after_registration",
        "crates/bacnet-transport/src/sc_hub/response_silence_tests.rs::unsolicited_responses_do_not_defer_idle_probe_or_its_original_timeout",
        "crates/bacnet-transport/src/sc_hub/response_silence_lifecycle_tests.rs::unsolicited_responses_mtls_keep_absolute_connect_deadline_and_release_admission",
        "crates/bacnet-transport/src/sc_hub/response_silence_lifecycle_tests.rs::unsolicited_responses_at_capacity_preserve_owners_then_allow_real_replacement",
    ]);
}

#[test]
fn hub_unknown_transit_evidence_keeps_family_scope_and_existing_lifecycle() {
    let data = ledger();
    let row = rows_by_id(&data)[ROW];
    assert_status(row, STATUS);
    assert_test_family(row, "unknown_transit", 11);
}

#[test]
fn hub_resolution_transit_is_unicast_hub_only_with_executable_evidence() {
    let data = ledger();
    let row = rows_by_id(&data)[ROW];
    assert_status(row, STATUS);
    assert_listed(
        row,
        "code_anchors",
        &[
            "crates/bacnet-transport/src/sc_hub/opaque_relay.rs",
            "crates/bacnet-transport/src/sc_hub/resolution_transit.rs",
            "crates/bacnet-transport/src/sc_hub/resolution_transit_tests.rs",
            "crates/bacnet-transport/src/sc_hub/resolution_transit_lifecycle_tests.rs",
        ],
    );
    assert_test_family(row, "resolution_transit", 12);
}
