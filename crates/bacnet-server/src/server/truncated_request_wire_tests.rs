//! What a peer receives for a confirmed request whose contents stop before
//! a member's header says they should (#1303, #1304).
//!
//! The decoders behind these services report such a member as a short
//! buffer, where some used to call it malformed. The server answers both
//! kinds alike, so each request here pins the reply a peer sees: SERVICES /
//! OTHER, as the plain Error PDU or, for SubscribeCOVPropertyMultiple, as its
//! general error choice. AV-1 is the Harness's Analog Value.
use super::*;
use crate::server::cov_wire_test_support::Harness;
use crate::server::test_transport::TestTransport;
use bacnet_encoding::apdu::ErrorPdu;
use bacnet_services::cov_multiple::SubscribeCOVPropertyMultipleError;

/// AV-1's object identifier as a primitive `[0]`.
const AV_1: [u8; 5] = [0x0C, 0x00, 0x80, 0x00, 0x01];

/// Whether `apdu` answers the request sent with `invoke_id`.
fn answers(apdu: &Apdu, invoke_id: u8) -> bool {
    match apdu {
        Apdu::SimpleAck(ack) => ack.invoke_id == invoke_id,
        Apdu::ComplexAck(ack) => ack.invoke_id == invoke_id,
        Apdu::Error(error) => error.invoke_id == invoke_id,
        Apdu::Reject(reject) => reject.invoke_id == invoke_id,
        Apdu::Abort(abort) => abort.invoke_id == invoke_id,
        _ => false,
    }
}

/// Send `body` as one confirmed `service` request and return the Error PDU
/// answering it, failing on any other answer.
async fn error_for(h: &mut Harness, service: ConfirmedServiceChoice, body: &[u8]) -> ErrorPdu {
    h.request(service, BytesMut::from(body)).await;
    let invoke_id = h.invoke_id;
    let answer = tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            let found = {
                let mut frames = h.frames.lock().unwrap();
                let at = frames.iter().position(|apdu| answers(apdu, invoke_id));
                at.map(|at| frames.remove(at))
            };
            match found {
                Some(apdu) => return apdu,
                None => tokio::time::sleep(Duration::from_millis(1)).await,
            }
        }
    })
    .await
    .expect("an answer to the request");
    match answer {
        Apdu::Error(error) => {
            assert_eq!(error.service_choice, service);
            assert_eq!(
                (error.error_class, error.error_code),
                (ErrorClass::SERVICES, ErrorCode::OTHER),
                "{service:?} {body:02X?}"
            );
            error
        }
        other => panic!("{service:?} {body:02X?} drew {other:?}"),
    }
}

#[tokio::test(start_paused = true)]
async fn read_property_multiple_cut_short_draws_services_other() {
    let mut h = Harness::start(ServerConfig::default()).await;
    let service = ConfirmedServiceChoice::READ_PROPERTY_MULTIPLE;
    // The object identifier with three of its four octets, then AV-1 with a
    // property identifier that says two octets and holds one.
    let reference_cut = [&AV_1[..], &[0x1E, 0x0A, 0x55]].concat();
    for body in [&AV_1[..4], &reference_cut] {
        let error = error_for(&mut h, service, body).await;
        assert!(error.error_data.is_empty());
    }
    h.server.stop().await.unwrap();
}

#[tokio::test(start_paused = true)]
async fn subscribe_cov_property_cut_short_draws_services_other() {
    let mut h = Harness::start(ServerConfig::default()).await;
    // Process 1 and AV-1 as `[1]`, then the `[4]` property reference cut
    // short.
    let body = [0x09, 0x01, 0x1C, 0x00, 0x80, 0x00, 0x01, 0x4E, 0x0A, 0x55];
    let error = error_for(
        &mut h,
        ConfirmedServiceChoice::SUBSCRIBE_COV_PROPERTY,
        &body,
    )
    .await;
    assert!(error.error_data.is_empty());
    h.server.stop().await.unwrap();
}

#[tokio::test(start_paused = true)]
async fn subscribe_cov_property_multiple_cut_short_draws_the_general_error() {
    let mut h = Harness::start(ServerConfig::default()).await;
    // Process 1, unconfirmed, then one specification for AV-1 whose first
    // `[0]` property reference is cut short.
    let body = [
        &[0x09, 0x01, 0x19, 0x00, 0x4E][..],
        &AV_1,
        &[0x1E, 0x0E, 0x0A, 0x55],
    ]
    .concat();
    let service = ConfirmedServiceChoice::SUBSCRIBE_COV_PROPERTY_MULTIPLE;
    let error = error_for(&mut h, service, &body).await;
    let formal = SubscribeCOVPropertyMultipleError::try_from(&error).unwrap();
    assert_eq!(formal.first_failed_subscription, None);
    h.server.stop().await.unwrap();
}

#[tokio::test(start_paused = true)]
async fn confirmed_audit_notification_cut_short_draws_services_other() {
    let mut h = Harness::start(ServerConfig::default()).await;
    let service = ConfirmedServiceChoice::CONFIRMED_AUDIT_NOTIFICATION;
    // `[0]` around one notification: source-device Device 1 in `[2]`, then a
    // source-object `[3]` of three octets, or of four with two present.
    let device = [0x2E, 0x0C, 0x02, 0x00, 0x00, 0x01, 0x2F];
    let three_octets = [&[0x0E][..], &device, &[0x3B, 0x00, 0x80, 0x00, 0x0F]].concat();
    let cut_short = [&[0x0E][..], &device, &[0x3C, 0x00, 0x80]].concat();
    for body in [three_octets, cut_short] {
        let error = error_for(&mut h, service, &body).await;
        assert!(error.error_data.is_empty());
    }
    h.server.stop().await.unwrap();
}

/// The mapping every refused confirmed request goes through answers a
/// decoder's two refusal kinds alike, whatever the service.
#[test]
fn malformed_and_cut_short_requests_draw_the_same_reply() {
    for raw in 0..=u8::MAX {
        let service = ConfirmedServiceChoice::from_raw(raw);
        let reply =
            |error: Error| BACnetServer::<TestTransport>::error_apdu_from_error(7, service, &error);
        assert_eq!(
            reply(Error::decoding(3, "malformed")),
            reply(Error::buffer_too_short(9, 4)),
            "{service:?}"
        );
    }
}

/// A `[0]` Unsigned announcing two contents octets and holding one.
const PROCESS_CUT: [u8; 2] = [0x0A, 0x01];

#[tokio::test(start_paused = true)]
async fn service_parameters_cut_short_draw_services_other() {
    let mut h = Harness::start(ServerConfig::default()).await;
    // AV-1, then a `[1]` property identifier cut the same way; and a `[0]`
    // object identifier with two of its four octets.
    let property_cut = [&AV_1[..], &[0x1A, 0x55]].concat();
    let object_cut = [0x0C, 0x00, 0x80];
    let cases: [(ConfirmedServiceChoice, &[u8]); 9] = [
        (ConfirmedServiceChoice::READ_PROPERTY, &property_cut),
        (ConfirmedServiceChoice::WRITE_PROPERTY, &property_cut),
        (ConfirmedServiceChoice::READ_RANGE, &object_cut),
        (ConfirmedServiceChoice::SUBSCRIBE_COV, &PROCESS_CUT),
        (ConfirmedServiceChoice::SUBSCRIBE_COV_PROPERTY, &PROCESS_CUT),
        (ConfirmedServiceChoice::ACKNOWLEDGE_ALARM, &PROCESS_CUT),
        (ConfirmedServiceChoice::GET_EVENT_INFORMATION, &object_cut),
        (ConfirmedServiceChoice::LIFE_SAFETY_OPERATION, &PROCESS_CUT),
        (ConfirmedServiceChoice::AUDIT_LOG_QUERY, &object_cut),
    ];
    for (service, body) in cases {
        let error = error_for(&mut h, service, body).await;
        assert!(error.error_data.is_empty(), "{service:?}");
    }
    h.server.stop().await.unwrap();
}

#[tokio::test(start_paused = true)]
async fn subscribe_cov_property_multiple_process_cut_short_draws_the_general_error() {
    let mut h = Harness::start(ServerConfig::default()).await;
    let service = ConfirmedServiceChoice::SUBSCRIBE_COV_PROPERTY_MULTIPLE;
    let error = error_for(&mut h, service, &PROCESS_CUT).await;
    let formal = SubscribeCOVPropertyMultipleError::try_from(&error).unwrap();
    assert_eq!(formal.first_failed_subscription, None);
    h.server.stop().await.unwrap();
}
