use super::*;
use crate::sc_frame::{decode_sc_bvlc_result, ScBvlcResult};

#[test]
fn bvlc_result_nak_uses_standard_error_values() {
    let nak = build_bvlc_result_nak(
        0x1234,
        ScFunction::ConnectRequest,
        ErrorClass::COMMUNICATION,
        ErrorCode::NODE_DUPLICATE_VMAC,
    );

    assert_eq!(
        decode_sc_bvlc_result(&nak).unwrap(),
        ScBvlcResult::Nak {
            result_for: ScFunction::ConnectRequest,
            error_header_marker: 0,
            error_class: 7,
            error_code: 151,
            error_details: String::new(),
        }
    );
}

#[test]
fn connect_request_rejects_hub_vmac_as_duplicate() {
    assert_eq!(
        connect_request_vmac_disposition([0x10; 6], [0x10; 6]),
        ConnectRequestVmacDisposition::Nak(
            ErrorClass::COMMUNICATION,
            ErrorCode::NODE_DUPLICATE_VMAC
        )
    );
    assert_eq!(
        connect_request_vmac_disposition([0x00; 6], [0x10; 6]),
        ConnectRequestVmacDisposition::CloseReserved
    );
    assert_eq!(
        connect_request_vmac_disposition([0x01; 6], [0x10; 6]),
        ConnectRequestVmacDisposition::Accept
    );
}

#[test]
fn relay_limit_decision_accepts_within_target_limits() {
    assert_eq!(
        relay_limit_decision(20, 40, 20, 40),
        RelayLimitDecision::Send
    );
}

#[test]
fn relay_limit_decision_rejects_oversized_npdu_first() {
    assert_eq!(
        relay_limit_decision(21, 41, 20, 40),
        RelayLimitDecision::DropMaxNpdu
    );
}

#[test]
fn relay_limit_decision_rejects_oversized_encoded_bvlc() {
    assert_eq!(
        relay_limit_decision(20, 41, 20, 40),
        RelayLimitDecision::DropMaxBvlc
    );
}

#[test]
fn known_unhandled_function_is_not_classified_as_unknown() {
    let nak = build_bvlc_result_nak(
        0x1234,
        ScFunction::ConnectAccept,
        ErrorClass::COMMUNICATION,
        unexpected_bvlc_function_error_code(ScFunction::ConnectAccept),
    );

    assert_eq!(
        decode_sc_bvlc_result(&nak).unwrap(),
        ScBvlcResult::Nak {
            result_for: ScFunction::ConnectAccept,
            error_header_marker: 0,
            error_class: 7,
            error_code: 150,
            error_details: String::new(),
        }
    );
    assert_eq!(
        unexpected_bvlc_function_error_code(ScFunction::Unknown(0x42)),
        ErrorCode::BVLC_FUNCTION_UNKNOWN
    );
}

#[test]
fn websocket_subprotocol_offer_accepts_hub_protocol_in_list() {
    let request = tokio_tungstenite::tungstenite::handshake::server::Request::builder()
        .header(
            "Sec-WebSocket-Protocol",
            format!("chat, {BACNET_SC_HUB_SUBPROTOCOL}, other"),
        )
        .body(())
        .unwrap();

    assert!(offers_websocket_subprotocol(
        &request,
        BACNET_SC_HUB_SUBPROTOCOL
    ));
}

#[test]
fn websocket_subprotocol_offer_rejects_missing_hub_protocol() {
    let request = tokio_tungstenite::tungstenite::handshake::server::Request::builder()
        .header("Sec-WebSocket-Protocol", "dc.bsc.bacnet.org")
        .body(())
        .unwrap();

    assert!(!offers_websocket_subprotocol(
        &request,
        BACNET_SC_HUB_SUBPROTOCOL
    ));

    let request_without_header =
        tokio_tungstenite::tungstenite::handshake::server::Request::builder()
            .body(())
            .unwrap();
    assert!(!offers_websocket_subprotocol(
        &request_without_header,
        BACNET_SC_HUB_SUBPROTOCOL
    ));
}

#[test]
fn websocket_subprotocol_error_response_is_bad_request() {
    let response = websocket_subprotocol_error_response();

    assert_eq!(
        response.status(),
        tokio_tungstenite::tungstenite::http::StatusCode::BAD_REQUEST
    );
    assert!(response
        .body()
        .as_ref()
        .unwrap()
        .contains(BACNET_SC_HUB_SUBPROTOCOL));
}
