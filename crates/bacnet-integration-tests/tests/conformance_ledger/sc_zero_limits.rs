//! The local zero-only capacity policy keeps its wire, lifecycle and native
//! evidence without promoting the connection-state row.
use super::*;

#[test]
fn zero_limit_policy_has_wire_lifecycle_and_native_evidence_without_promotion() {
    let data = ledger();
    let row = rows_by_id(&data)["BACNET-AB-SC-CONNECTION-STATE"];
    assert_status(row, "implementation-present-needs-state-machine-audit");
    assert_listed(
        row,
        "code_anchors",
        &[
            "crates/bacnet-transport/src/sc_frame/connect_test_support.rs",
            "crates/bacnet-transport/src/sc_hub/peer_uuid_tests.rs",
        ],
    );
    assert_listed(row, "positive_tests", &[
        "crates/bacnet-transport/src/sc_frame/connect.rs::tests::positive_limits_remain_independent_without_a_serviceability_floor",
        "crates/bacnet-transport/src/sc/connect_validation_tests.rs::connect_accept_positive_limits_commit_without_normalization",
        "crates/bacnet-transport/src/sc_hub/peer_uuid_tests.rs::positive_limits_mtls_request_commits_exact_peer_capacities",
        "crates/rusty-bacnet/tests/test_sc_zero_limits.py::ZeroLimitsTests::test_native_nodes_zero_limits_wait_silently_then_recover",
    ]);
    assert_listed(row, "negative_tests", &[
        "crates/bacnet-transport/src/sc_frame/connect.rs::tests::zero_limits_rejection_is_receive_admission_not_codec_policy",
        "crates/bacnet-transport/src/sc/connect_validation_tests.rs::connect_accept_zero_limits_is_transactional_in_every_state",
        "crates/bacnet-transport/src/sc/connect_validation_tests.rs::connect_accept_zero_limits_only_and_flood_keep_absolute_deadline",
        "crates/bacnet-transport/src/sc/reconnect_validation_tests.rs::zero_limits_accept_failover_and_failed_primary_probe_preserve_active_identity_and_limits",
        "crates/bacnet-transport/src/sc_hub/peer_uuid_tests.rs::zero_limits_mtls_collision_at_capacity_preserves_live_peers",
        "crates/bacnet-transport/src/sc_hub/deadline_commit_tests.rs::zero_limits_flood_cannot_extend_blocked_nak_connect_deadline",
        "crates/rusty-bacnet/tests/test_sc_zero_limits.py::ZeroLimitsTests::test_native_nodes_zero_limits_expire_without_connecting",
        "crates/rusty-bacnet/tests/test_sc_zero_limits.py::ZeroLimitsTests::test_native_hub_zero_limits_preserve_known_uuid_owner_and_repeat",
    ]);
    assert_open_work_recorded(row);
}
