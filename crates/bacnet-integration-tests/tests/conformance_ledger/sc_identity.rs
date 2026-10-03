//! SC credential, device-identity and peer-UUID evidence stays listed in its
//! rows, and the rows keep their partial statuses.
use super::*;

const TLS_ROW: &str = "BACNET-AB-SC-WEBSOCKET-TLS";
const TLS_STATUS: &str = "implementation-present-needs-security-tests";
const CONNECTION_ROW: &str = "BACNET-AB-SC-CONNECTION-STATE";
const CONNECTION_STATUS: &str = "implementation-present-needs-state-machine-audit";

#[test]
fn sc_credential_evidence_does_not_promote_the_full_security_profile() {
    let data = ledger();
    let row = rows_by_id(&data)[TLS_ROW];
    assert_status(row, TLS_STATUS);
    assert_listed(row, "negative_tests", &[
        "crates/bacnet-transport/tests/sc_hub_tls.rs::typed_config_rejects_empty_ca_before_startup",
        "crates/bacnet-transport/src/sc_tls/tls_config_tests.rs::node_tls_factory_requires_nonempty_ca_and_identity",
        "crates/rusty-bacnet/tests/test_sc_hub_mtls.py::HubMtlsTests::test_invalid_files_fail_before_bind",
        "crates/rusty-bacnet/tests/test_sc_hub_mtls.py::NodeMtlsTests::test_invalid_local_files_do_not_dial_or_drain",
        "crates/bacnet-cli/tests/sc_ca.rs::missing_ca_rejected_before_dial",
    ]);
}

#[test]
fn sc_identity_evidence_stays_listed_without_status_promotion() {
    let data = ledger();
    let row = rows_by_id(&data)[TLS_ROW];
    assert_status(row, TLS_STATUS);
    assert_listed(row, "positive_tests", &[
        "crates/rusty-bacnet/tests/test_sc_hub_mtls.py::NodeIdentityMtlsTests::test_uuid_owned_wire_bytes_across_stop_start_and_recreation",
        "crates/rusty-bacnet/tests/test_sc_hub_mtls.py::NodeIdentityMtlsTests::test_distinct_nodes_and_same_uuid_replacement_leave_other_node_usable",
        "benchmarks/tests/sc_mtls/node_identity.rs::sc_server_uuid_wire_bytes_survive_reconnect_and_fresh_builds",
        "crates/bacnet-transport/tests/sc_hub_tls.rs::local_hub_identity_wire_bytes_survive_fresh_start_on_every_api",
        "crates/rusty-bacnet/tests/test_sc_hub_mtls.py::NodeIdentityMtlsTests::test_hub_owned_identity_survives_stop_start_and_fresh_object",
        "benchmarks/tests/sc_binary/handshake.rs::hub_identity_is_explicit_and_stable_across_binary_restart",
    ]);
    assert_open_work_recorded(row);
}

#[test]
fn sc_hub_identity_evidence_retains_pre_io_checks_and_no_status_promotion() {
    let data = ledger();
    let row = rows_by_id(&data)[TLS_ROW];
    assert_status(row, TLS_STATUS);
    assert_listed(row, "negative_tests", &[
        "crates/bacnet-transport/tests/sc_hub_tls.rs::local_hub_identity_rejected_before_bind_on_every_start_api",
        "crates/rusty-bacnet/tests/test_sc_hub_identity.py::HubIdentityTests::test_uuid_required_length_zero_and_vmac_errors_precede_io",
        "crates/rusty-bacnet/tests/test_sc_hub_identity.py::HubIdentityTests::test_installed_hub_stub_matches_runtime_keyword_contract",
        "benchmarks/tests/sc_binary/preflight.rs::missing_empty_and_invalid_identity_precede_file_or_network_io",
    ]);
}

#[test]
fn sc_raw_identity_evidence_retains_startup_only_boundary() {
    let data = ledger();
    let row = rows_by_id(&data)[TLS_ROW];
    assert_listed(row, "negative_tests", &[
        "crates/bacnet-transport/src/sc/identity_tests.rs::explicit_zero_uuid_rejected_without_io_and_repaired_on_same_socket",
        "crates/bacnet-transport/src/sc/identity_tests.rs::zero_vmac_rejected_without_io_or_socket_consumption",
        "crates/bacnet-transport/src/sc/identity_tests.rs::broadcast_vmac_rejected_without_io_or_socket_consumption",
        "crates/bacnet-transport/src/sc/identity_tests.rs::reconnect_then_heartbeat_then_identity_error_precedence",
    ]);
}

/// The device-identity closeout (#517) rests on these tests; the row keeps
/// them while the closeout text moves into the row (#1208).
#[test]
fn sc_identity_closeout_evidence_stays_listed_without_status_promotion() {
    let data = ledger();
    let row = rows_by_id(&data)[TLS_ROW];
    assert_status(row, TLS_STATUS);
    assert_listed(row, "positive_tests", &[
        "crates/rusty-bacnet/tests/test_sc_hub_mtls.py::NodeIdentityMtlsTests::test_distinct_nodes_and_same_uuid_replacement_leave_other_node_usable",
        "crates/rusty-bacnet/tests/test_sc_hub_mtls.py::NodeIdentityMtlsTests::test_uuid_owned_wire_bytes_across_stop_start_and_recreation",
        "crates/bacnet-transport/tests/sc_hub_tls.rs::strict_hub_start_family_requires_mutual_tls13_and_preserves_uuid",
    ]);
    assert_listed(row, "negative_tests", &[
        "crates/rusty-bacnet/tests/test_sc_node_identity.py::NodeIdentityConstructorTests::test_sc_uuid_validation_precedes_file_and_socket_io",
    ]);
}

#[test]
fn sc_peer_uuid_evidence_retains_silent_accept_policy_without_status_promotion() {
    let data = ledger();
    let row = rows_by_id(&data)[CONNECTION_ROW];
    assert_status(row, CONNECTION_STATUS);
    assert_listed(
        row,
        "code_anchors",
        &[
            "crates/bacnet-transport/src/sc/connect_validation_tests.rs",
            "crates/bacnet-transport/src/sc/reconnect_validation_tests.rs",
            "crates/bacnet-transport/src/sc_tls/connect_accept_tests.rs",
        ],
    );
    assert_listed(row, "negative_tests", &[
        "crates/bacnet-transport/src/sc_hub/peer_uuid_tests.rs::zero_uuid_mtls_request_never_reaches_admission",
        "crates/bacnet-transport/src/sc_hub/peer_uuid_tests.rs::zero_uuid_mtls_collision_at_capacity_preserves_live_peers",
        "crates/bacnet-transport/src/sc_hub/peer_uuid_tests.rs::zero_uuid_mtls_repeat_flood_preserves_activity_probe_and_registration",
        "crates/rusty-bacnet/tests/test_sc_peer_uuid.py::PeerUuidTests::test_nil_request_nak_close_repeat_and_surviving_native_read",
        "crates/bacnet-transport/src/sc/connect_validation_tests.rs::connect_accept_zero_uuid_is_transactional_in_every_state",
        "crates/bacnet-transport/src/sc/connect_validation_tests.rs::connect_accept_nil_only_and_flood_keep_absolute_deadline",
        "crates/bacnet-transport/src/sc/connect_validation_tests.rs::connect_accept_nil_wrong_id_is_discarded_but_valid_wrong_id_is_terminal",
        "crates/bacnet-transport/src/sc/reconnect_validation_tests.rs::nil_accept_failover_and_failed_primary_probe_preserve_active_identity_and_limits",
        "crates/bacnet-transport/src/sc/reconnect_validation_tests.rs::nil_accept_reconnect_probe_times_out_then_redials_without_reseeding",
        "crates/bacnet-transport/src/sc_tls/connect_accept_tests.rs::nil_accept_tls_expires_without_peer_identity_or_limits",
        "crates/rusty-bacnet/tests/test_sc_accept_uuid.py::AcceptUuidTests::test_native_nodes_nil_accept_expires_without_connecting",
    ]);
    assert_listed(row, "positive_tests", &[
        "crates/bacnet-transport/src/sc_frame/connect.rs::tests::nonzero_uuid_bits_remain_opaque",
        "crates/bacnet-transport/src/sc/connect_validation_tests.rs::connect_accept_invalid_matrix_waits_silently_for_valid_accept",
        "crates/bacnet-transport/src/sc_tls/connect_accept_tests.rs::nil_accept_tls_is_silent_until_later_valid_accept",
        "crates/rusty-bacnet/tests/test_sc_accept_uuid.py::AcceptUuidTests::test_native_nodes_wait_silently_then_accept_valid_uuid",
    ]);
    assert_open_work_recorded(row);
}
