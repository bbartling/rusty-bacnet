//! Node rejection evidence remains bounded local policy, not a status promotion.
use super::*;

const ROW: &str = "BACNET-AB-SC-CONNECTION-STATE";
const STATUS: &str = "implementation-present-needs-state-machine-audit";

#[test]
fn mu_liveness_evidence_preserves_scope_and_blocked_write_limitation() {
    let data = ledger();
    let row = rows_by_id(&data)[ROW];
    assert_status(row, STATUS);
    assert_listed(row, "positive_tests", &[
        "crates/bacnet-transport/src/sc/mu_liveness_tests.rs::mu_liveness_valid_npdu_data_options_and_heartbeat_request_restore_activity",
        "crates/bacnet-transport/src/sc_tls/mu_liveness_tests.rs::mu_liveness_tls_wire_rejection_and_healthy_recovery",
        "crates/rusty-bacnet/tests/test_sc_mu_liveness.py::MuLivenessTests::test_mu_rejection_then_healthy_native_read_property",
    ]);
    assert_listed(row, "negative_tests", &[
        "crates/bacnet-transport/src/sc/mu_liveness_tests.rs::mu_liveness_rejected_burst_preserves_pending_probe_and_matching_ack",
        "crates/bacnet-transport/src/sc/mu_liveness_tests.rs::mu_liveness_rejected_traffic_keeps_original_idle_timeout_and_reconnects",
        "crates/bacnet-transport/src/sc/mu_liveness_tests.rs::mu_liveness_source_and_control_admission_still_precede_mu",
    ]);
    assert_open_work_recorded(row);
}

#[test]
fn rejection_nak_budget_evidence_preserves_freshness_and_cancellation_limits() {
    let data = ledger();
    let row = rows_by_id(&data)[ROW];
    assert_status(row, STATUS);
    assert_listed(
        row,
        "code_anchors",
        &[
            "crates/bacnet-transport/src/sc/rejection.rs",
            "crates/bacnet-transport/src/sc/recovery.rs",
            "crates/bacnet-transport/src/sc_tls/rejection_deadline_tests.rs",
        ],
    );
    assert_test_family(row, "rejection_deadline", 19);
}

#[test]
fn empty_npdu_evidence_preserves_zero_only_scope_and_existing_lifecycle_owners() {
    let data = ledger();
    let row = rows_by_id(&data)[ROW];
    assert_status(row, STATUS);
    assert_test_family(row, "empty_npdu", 13);
}

#[test]
fn unknown_function_evidence_preserves_node_only_scope_and_fifth_budget_path() {
    let data = ledger();
    let row = rows_by_id(&data)[ROW];
    assert_status(row, STATUS);
    assert_test_family(row, "unknown_function", 11);
}
