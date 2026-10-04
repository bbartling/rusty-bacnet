//! What a peer receives for a request with octets after its last member
//! (#1411).
//!
//! The decoders refuse such a request as malformed, and the server answers
//! it as it answers any request it can't decode: SERVICES / OTHER, with
//! nothing read, written, deleted or changed. A GetAlarmSummary has no
//! parameters at all, so any octet in it is trailing. A confirmed request
//! is refused before its password or the server's policy is looked at. An
//! unconfirmed request with trailing octets is dropped, since nothing can
//! answer it: a Who-Is gets no I-Am, a Who-Has no I-Have, and an I-Am binds
//! no device.
use super::*;
use crate::server::cov_wire_test_support::{av1, Harness};
use crate::server::mistagged_request_wire_tests::{
    contents, harness, request, FILE_1, FILE_2, READ, WRITE,
};
use crate::server::truncated_request_wire_tests::{answer_to, error_for};
use bacnet_services::device_mgmt::{DeviceCommunicationControlRequest, ReinitializeDeviceRequest};
use bacnet_types::enums::{EnableDisable, ReinitializedState};

/// AV-1 as an application object identifier.
const AV_1: [u8; 5] = [0xC4, 0x00, 0x80, 0x00, 0x01];
/// "secret" as an application CharacterString, where the services want it
/// under a context tag.
const SECRET_APPLICATION: [u8; 9] = [0x75, 0x07, 0x00, b's', b'e', b'c', b'r', b'e', b't'];

#[tokio::test(start_paused = true)]
async fn file_requests_with_trailing_octets_draw_services_other() {
    let mut h = harness().await;
    // The well-formed requests these extend are served (see
    // mistagged_file_requests_draw_services_other); the writes below carry
    // 0x42, which neither file holds, so any of them carried out would show.
    let before = contents(&h).await;
    let cases: [(ConfirmedServiceChoice, &str, Vec<u8>); 9] = [
        (
            READ,
            "an octet after the stream frame",
            request(FILE_1, &[0x0E, 0x31, 0x05, 0x21, 0x10, 0x0F, 0x00]),
        ),
        (
            READ,
            "a member after the octet count",
            request(FILE_1, &[0x0E, 0x31, 0x05, 0x21, 0x10, 0x21, 0x01, 0x0F]),
        ),
        (
            READ,
            "an octet after the record frame",
            request(FILE_2, &[0x1E, 0x31, 0x00, 0x21, 0x02, 0x1F, 0x00]),
        ),
        (
            READ,
            "a member after the record count",
            request(FILE_2, &[0x1E, 0x31, 0x00, 0x21, 0x02, 0x21, 0x01, 0x1F]),
        ),
        (
            WRITE,
            "an octet after the stream frame",
            request(FILE_1, &[0x0E, 0x31, 0x05, 0x62, 0x00, 0x42, 0x0F, 0x00]),
        ),
        (
            WRITE,
            "a member after the file data",
            request(
                FILE_1,
                &[0x0E, 0x31, 0x05, 0x62, 0x00, 0x42, 0x21, 0x01, 0x0F],
            ),
        ),
        (
            WRITE,
            "a second stream frame",
            request(
                FILE_1,
                &[
                    0x0E, 0x31, 0x05, 0x62, 0x00, 0x42, 0x0F, 0x0E, 0x31, 0x07, 0x62, 0x00, 0x42,
                    0x0F,
                ],
            ),
        ),
        (
            WRITE,
            "an octet after the record frame",
            request(
                FILE_2,
                &[0x1E, 0x31, 0x00, 0x21, 0x01, 0x62, 0x00, 0x42, 0x1F, 0x00],
            ),
        ),
        (
            WRITE,
            "a record frame after the stream frame",
            request(
                FILE_1,
                &[
                    0x0E, 0x31, 0x05, 0x62, 0x00, 0x42, 0x0F, 0x1E, 0x31, 0x00, 0x21, 0x00, 0x1F,
                ],
            ),
        ),
    ];
    for (service, what, body) in &cases {
        let error = error_for(&mut h, *service, body).await;
        assert!(error.error_data.is_empty(), "{service:?} {what}");
    }
    assert_eq!(contents(&h).await, before);
    h.server.stop().await.unwrap();
}

#[tokio::test(start_paused = true)]
async fn delete_object_with_trailing_octets_draws_services_other() {
    let mut h = Harness::start(ServerConfig::default()).await;
    let delete = ConfirmedServiceChoice::DELETE_OBJECT;
    for (what, tail) in [
        ("an octet", &[0x00][..]),
        ("a second identifier", &AV_1[..]),
    ] {
        let error = error_for(&mut h, delete, &[&AV_1[..], tail].concat()).await;
        assert!(error.error_data.is_empty(), "{what}");
        assert!(
            h.server.database().read().await.get(&av1()).is_some(),
            "{what}"
        );
    }
    let answer = answer_to(&mut h, delete, &AV_1).await;
    assert!(matches!(answer, Apdu::SimpleAck(_)), "{answer:?}");
    assert!(h.server.database().read().await.get(&av1()).is_none());
    h.server.stop().await.unwrap();
}

/// A DeviceCommunicationControl body with password "secret", then `tail`.
fn dcc(mode: EnableDisable, minutes: Option<u16>, tail: &[u8]) -> Vec<u8> {
    let mut body = BytesMut::new();
    DeviceCommunicationControlRequest {
        time_duration: minutes,
        enable_disable: mode,
        password: Some("secret".into()),
    }
    .encode(&mut body)
    .unwrap();
    body.extend_from_slice(tail);
    body.to_vec()
}

/// The server's DCC state and whether a DCC timer is running.
async fn dcc_state(h: &Harness) -> (DccState, bool) {
    (
        h.server.comm_state(),
        !h.server.dcc_timer.lock().await.is_none(),
    )
}

#[tokio::test(start_paused = true)]
async fn dcc_with_trailing_octets_draws_services_other_and_changes_nothing() {
    let mut h = Harness::start(ServerConfig {
        dcc_policy: DccPolicy::RequirePassword,
        dcc_password: Some("secret".into()),
        ..Default::default()
    })
    .await;
    let service = ConfirmedServiceChoice::DEVICE_COMMUNICATION_CONTROL;
    let restrict = EnableDisable::DISABLE_INITIATION;
    let (enabled, restricted) = (DccState::Enable, DccState::DisableInitiation);
    // Five minutes of DISABLE_INITIATION with the right password, then an
    // octet or a `[3]`; and the password under its application tag, which
    // leaves it unread.
    let cases: [(&str, Vec<u8>); 3] = [
        (
            "an octet after the password",
            dcc(restrict, Some(5), &[0x00]),
        ),
        (
            "a [3] after the password",
            dcc(restrict, Some(5), &[0x39, 0x07]),
        ),
        (
            "the password as an application CharacterString",
            [&[0x09, 0x05, 0x19, 0x02][..], &SECRET_APPLICATION].concat(),
        ),
    ];
    for (what, body) in &cases {
        let error = error_for(&mut h, service, body).await;
        assert!(error.error_data.is_empty(), "{what}");
        assert_eq!(dcc_state(&h).await, (enabled, false), "{what}");
    }
    let answer = answer_to(&mut h, service, &dcc(restrict, Some(5), &[])).await;
    assert!(matches!(answer, Apdu::SimpleAck(_)), "{answer:?}");
    assert_eq!(dcc_state(&h).await, (restricted, true));
    // An ENABLE with trailing octets leaves initiation restricted too.
    let enable = EnableDisable::ENABLE;
    let error = error_for(&mut h, service, &dcc(enable, None, &[0x00])).await;
    assert!(error.error_data.is_empty());
    assert_eq!(dcc_state(&h).await, (restricted, true));
    let answer = answer_to(&mut h, service, &dcc(enable, None, &[])).await;
    assert!(matches!(answer, Apdu::SimpleAck(_)), "{answer:?}");
    assert_eq!(dcc_state(&h).await, (enabled, false));
    h.server.stop().await.unwrap();
}

/// A ReinitializeDevice body for WARMSTART with `password`, then `tail`.
fn reinitialize(password: Option<&str>, tail: &[u8]) -> Vec<u8> {
    let mut body = BytesMut::new();
    ReinitializeDeviceRequest {
        reinitialized_state: ReinitializedState::WARMSTART,
        password: password.map(str::to_owned),
    }
    .encode(&mut body)
    .unwrap();
    body.extend_from_slice(tail);
    body.to_vec()
}

#[tokio::test(start_paused = true)]
async fn reinitialize_device_with_trailing_octets_draws_services_other() {
    let mut h = Harness::start(ServerConfig {
        reinit_password: Some("secret".into()),
        ..Default::default()
    })
    .await;
    let service = ConfirmedServiceChoice::REINITIALIZE_DEVICE;
    // The server never reinitializes: a well-formed request with the right
    // password is refused as SERVICE_REQUEST_DENIED.
    match answer_to(&mut h, service, &reinitialize(Some("secret"), &[])).await {
        Apdu::Error(error) => assert_eq!(
            (error.error_class, error.error_code),
            (ErrorClass::SERVICES, ErrorCode::SERVICE_REQUEST_DENIED)
        ),
        other => panic!("{other:?}"),
    }
    // Each of these is refused for its trailing octets before the password
    // is checked.
    let cases: [(&str, Vec<u8>); 4] = [
        (
            "an octet after the right password",
            reinitialize(Some("secret"), &[0x00]),
        ),
        (
            "an octet after a wrong password",
            reinitialize(Some("wrong"), &[0x00]),
        ),
        (
            "the password as an application CharacterString",
            reinitialize(None, &SECRET_APPLICATION),
        ),
        ("a [2] after the state", reinitialize(None, &[0x29, 0x01])),
    ];
    for (what, body) in &cases {
        let error = error_for(&mut h, service, body).await;
        assert!(error.error_data.is_empty(), "{what}");
        assert_eq!(dcc_state(&h).await, (DccState::Enable, false), "{what}");
    }
    h.server.stop().await.unwrap();
}

#[tokio::test(start_paused = true)]
async fn get_alarm_summary_with_any_octet_draws_services_other() {
    let mut h = Harness::start(ServerConfig::default()).await;
    let service = ConfirmedServiceChoice::GET_ALARM_SUMMARY;
    let answer = answer_to(&mut h, service, &[]).await;
    assert!(matches!(answer, Apdu::ComplexAck(_)), "{answer:?}");
    for body in [&[0x00][..], &[0x09, 0x00]] {
        let error = error_for(&mut h, service, body).await;
        assert!(error.error_data.is_empty(), "{body:02X?}");
    }
    h.server.stop().await.unwrap();
}

/// The server serves no ConfirmedPrivateTransfer, so trailing octets don't
/// change its answer; the decoders' refusal reaches only their callers.
#[tokio::test(start_paused = true)]
async fn confirmed_private_transfer_stays_unrecognized() {
    let mut h = Harness::start(ServerConfig::default()).await;
    let service = ConfirmedServiceChoice::CONFIRMED_PRIVATE_TRANSFER;
    for body in [
        &[0x09, 0x07, 0x19, 0x01][..],
        &[0x09, 0x07, 0x19, 0x01, 0x00],
    ] {
        match answer_to(&mut h, service, body).await {
            Apdu::Reject(reject) => assert_eq!(
                reject.reject_reason,
                RejectReason::UNRECOGNIZED_SERVICE,
                "{body:02X?}"
            ),
            other => panic!("{body:02X?}: {other:?}"),
        }
    }
    h.server.stop().await.unwrap();
}

/// Deliver an unconfirmed request from the harness peer, let the server run
/// what it makes ready, and return the services of the unconfirmed requests
/// it sent the peer since.
async fn unconfirmed(
    h: &Harness,
    service_choice: UnconfirmedServiceChoice,
    body: &[u8],
) -> Vec<UnconfirmedServiceChoice> {
    h.respond(Apdu::UnconfirmedRequest(UnconfirmedRequestPdu {
        service_choice,
        service_request: Bytes::copy_from_slice(body),
    }))
    .await;
    h.settle().await;
    let mut sent = Vec::new();
    h.frames.lock().unwrap().retain(|apdu| match apdu {
        Apdu::UnconfirmedRequest(request) => {
            sent.push(request.service_choice);
            false
        }
        _ => true,
    });
    sent
}

#[tokio::test(start_paused = true)]
async fn who_is_and_who_has_with_trailing_octets_are_dropped() {
    let mut h = Harness::start(ServerConfig::default()).await;
    let who_is = UnconfirmedServiceChoice::WHO_IS;
    // Limits 0 to 1000, which take in the harness device (856).
    let limits = [0x09, 0x00, 0x1A, 0x03, 0xE8];
    for (what, body) in [
        ("an octet after the limits", [&limits[..], &[0x00]].concat()),
        ("a [2] alone", vec![0x29, 0x00]),
        (
            "limits as application Unsigneds",
            vec![0x21, 0x00, 0x22, 0x03, 0xE8],
        ),
    ] {
        assert_eq!(unconfirmed(&h, who_is, &body).await, [], "{what}");
    }
    assert_eq!(
        unconfirmed(&h, who_is, &limits).await,
        [UnconfirmedServiceChoice::I_AM]
    );

    let who_has = UnconfirmedServiceChoice::WHO_HAS;
    // AV-1 by name.
    let by_name = [0x3D, 0x05, 0x00, b'A', b'V', b'-', b'1'];
    let trailing = [&by_name[..], &[0x00]].concat();
    assert_eq!(unconfirmed(&h, who_has, &trailing).await, []);
    assert_eq!(
        unconfirmed(&h, who_has, &by_name).await,
        [UnconfirmedServiceChoice::I_HAVE]
    );
    let counters = h.server.discovery_counters();
    assert_eq!(
        (counters.who_is_received, counters.who_has_received),
        (1, 1)
    );
    h.server.stop().await.unwrap();
}

#[tokio::test(start_paused = true)]
async fn an_i_am_with_trailing_octets_binds_nothing() {
    let mut h = Harness::start(ServerConfig::default()).await;
    let i_am = UnconfirmedServiceChoice::I_AM;
    // Device 1234, max APDU 1476, no segmentation, vendor 42.
    let body = [
        0xC4, 0x02, 0x00, 0x04, 0xD2, 0x22, 0x05, 0xC4, 0x91, 0x03, 0x21, 0x2A,
    ];
    let bindings = h.server.device_bindings.read().await.len();
    unconfirmed(&h, i_am, &[&body[..], &[0x00]].concat()).await;
    assert_eq!(h.server.device_bindings.read().await.len(), bindings);
    unconfirmed(&h, i_am, &body).await;
    assert_eq!(h.server.device_bindings.read().await.len(), bindings + 1);
    h.server.stop().await.unwrap();
}
