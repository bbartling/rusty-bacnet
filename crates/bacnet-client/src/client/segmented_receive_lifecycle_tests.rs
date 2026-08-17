//! A reassembly session lives exactly as long as its transaction (#367).
//!
//! Clause 5.4.4.4 SEGMENTED_CONF ends by AbortPDU_Received (peer Abort with
//! 'server' = TRUE), by UnexpectedPDU_Received (Error and Reject PDUs are in
//! its list), or locally — and every ending is "enter the IDLE state", where
//! 5.4.4.1 answers further segments with Abort INVALID_APDU_IN_THIS_STATE.
//! Before #367's fix, none of those endings removed the `seg_state` entry, so
//! the client kept acking segments of a transaction that no longer existed.
//!
//! The tests run a real client over a loopback pair; the test plays the
//! server. Wall-clock discipline: each test finishes well inside the 4 s
//! reassembly reaper, and the caller-timeout test asserts the Abort reason so
//! a reaper eviction (TSM_TIMEOUT) cannot satisfy it for the wrong cause.

use bacnet_encoding::apdu::{self, encode_apdu, AbortPdu, Apdu, ComplexAck, ErrorPdu, RejectPdu};
use bacnet_encoding::npdu::{decode_npdu, encode_npdu, Npdu};
use bacnet_transport::loopback::LoopbackTransport;
use bacnet_transport::port::{ReceivedNpdu, TransportPort};
use bacnet_types::enums::{
    AbortReason, ConfirmedServiceChoice, ErrorClass, ErrorCode, RejectReason,
};
use bacnet_types::error::Error;
use bytes::{Bytes, BytesMut};
use tokio::sync::mpsc;
use tokio::task::JoinHandle;
use tokio::time::{timeout, Duration};

use super::{BACnetClient, ClientConfig};

const CLIENT_MAC: &[u8] = &[0x01];
const SERVER_MAC: &[u8] = &[0x02];

async fn send_to_client<T: TransportPort>(transport: &T, apdu: &Apdu) {
    let mut apdu_buf = BytesMut::new();
    encode_apdu(&mut apdu_buf, apdu).expect("valid APDU encoding");
    let npdu = Npdu {
        payload: apdu_buf.freeze(),
        ..Npdu::default()
    };
    let mut npdu_buf = BytesMut::new();
    encode_npdu(&mut npdu_buf, &npdu).unwrap();
    transport.send_unicast(&npdu_buf, CLIENT_MAC).await.unwrap();
}

async fn recv_apdu(rx: &mut mpsc::Receiver<ReceivedNpdu>, context: &str) -> Apdu {
    let received = timeout(Duration::from_secs(2), rx.recv())
        .await
        .unwrap_or_else(|_| panic!("{context}: timed out waiting for a PDU"))
        .unwrap_or_else(|| panic!("{context}: channel closed"));
    let npdu = decode_npdu(received.npdu).unwrap();
    apdu::decode_apdu(npdu.payload).unwrap()
}

fn response_segment(invoke_id: u8, seq: u8, more_follows: bool, data: &[u8]) -> Apdu {
    Apdu::ComplexAck(ComplexAck {
        segmented: true,
        more_follows,
        invoke_id,
        sequence_number: Some(seq),
        proposed_window_size: Some(1),
        service_choice: ConfirmedServiceChoice::READ_PROPERTY,
        service_ack: Bytes::copy_from_slice(data),
    })
}

/// Start a client, issue a ReadProperty, and hand back the peer side with the
/// request's invoke ID already consumed from the stream.
async fn start_reassembly(
    config: ClientConfig,
) -> (
    JoinHandle<(BACnetClient<LoopbackTransport>, Result<Bytes, Error>)>,
    LoopbackTransport,
    mpsc::Receiver<ReceivedNpdu>,
    u8,
) {
    let (client_transport, mut server_transport) =
        LoopbackTransport::pair(CLIENT_MAC.to_vec(), SERVER_MAC.to_vec());
    let mut server_rx = server_transport.start().await.unwrap();
    let mut client = BACnetClient::start(config, client_transport).await.unwrap();

    // The client rides along in the task's return value: several tests need
    // it alive (and its dispatch loop running) after the caller has already
    // returned, so it is stopped by the test, never by the task.
    let request_task = tokio::spawn(async move {
        let result = client
            .confirmed_request(
                SERVER_MAC,
                ConfirmedServiceChoice::READ_PROPERTY,
                &[0x0C; 8],
            )
            .await;
        (client, result)
    });

    let invoke_id = match recv_apdu(&mut server_rx, "the ReadProperty request").await {
        Apdu::ConfirmedRequest(req) => {
            assert!(!req.segmented);
            req.invoke_id
        }
        other => panic!("expected ConfirmedRequest, got {other:?}"),
    };
    (request_task, server_transport, server_rx, invoke_id)
}

async fn expect_segment_ack(rx: &mut mpsc::Receiver<ReceivedNpdu>, invoke_id: u8, seq: u8) {
    match recv_apdu(rx, &format!("ack for response segment {seq}")).await {
        Apdu::SegmentAck(ack) => {
            assert!(!ack.negative_ack);
            assert!(!ack.sent_by_server, "a client's SegmentAck is server=FALSE");
            assert_eq!(ack.invoke_id, invoke_id);
            assert_eq!(ack.sequence_number, seq);
        }
        other => panic!("expected SegmentAck for segment {seq}, got {other:?}"),
    }
}

async fn expect_client_abort(rx: &mut mpsc::Receiver<ReceivedNpdu>, invoke_id: u8, context: &str) {
    match recv_apdu(rx, context).await {
        Apdu::Abort(abort) => {
            assert!(
                !abort.sent_by_server,
                "{context}: a client's Abort is server=FALSE"
            );
            assert_eq!(abort.invoke_id, invoke_id, "{context}");
            assert_eq!(
                abort.abort_reason,
                AbortReason::INVALID_APDU_IN_THIS_STATE,
                "{context}"
            );
        }
        other => panic!("{context}: expected Abort, got {other:?}"),
    }
}

/// #367's failure case: the peer Aborts mid-reassembly, then keeps sending.
/// The session must die with the transaction — a further segment draws the
/// 5.4.4.1 Abort, never a SegmentAck.
#[tokio::test]
async fn peer_abort_ends_the_reassembly_session() {
    let (task, server, mut rx, invoke_id) = start_reassembly(ClientConfig::default()).await;

    send_to_client(&server, &response_segment(invoke_id, 0, true, &[0x01; 8])).await;
    expect_segment_ack(&mut rx, invoke_id, 0).await;

    send_to_client(
        &server,
        &Apdu::Abort(AbortPdu {
            sent_by_server: true,
            invoke_id,
            abort_reason: AbortReason::BUFFER_OVERFLOW,
        }),
    )
    .await;

    send_to_client(&server, &response_segment(invoke_id, 1, true, &[0x02; 8])).await;
    expect_client_abort(&mut rx, invoke_id, "a segment after the peer's Abort").await;

    let (mut client, result) = timeout(Duration::from_secs(2), task)
        .await
        .unwrap()
        .unwrap();
    match result {
        Err(Error::Abort { reason }) => {
            assert_eq!(reason, AbortReason::BUFFER_OVERFLOW.to_raw())
        }
        other => panic!("expected Err(Abort), got {other:?}"),
    }
    client.stop().await.unwrap();
}

/// An Error PDU mid-reassembly is Clause 5.4.4.4 UnexpectedPDU_Received: the
/// peer gets an Abort, the caller gets the ABORT.indication — not the error
/// content — and the session ends.
#[tokio::test]
async fn error_pdu_mid_reassembly_aborts_the_transfer() {
    let (task, server, mut rx, invoke_id) = start_reassembly(ClientConfig::default()).await;

    send_to_client(&server, &response_segment(invoke_id, 0, true, &[0x01; 8])).await;
    expect_segment_ack(&mut rx, invoke_id, 0).await;

    send_to_client(
        &server,
        &Apdu::Error(ErrorPdu {
            invoke_id,
            service_choice: ConfirmedServiceChoice::READ_PROPERTY,
            error_class: ErrorClass::DEVICE,
            error_code: ErrorCode::OPERATIONAL_PROBLEM,
            error_data: Bytes::new(),
        }),
    )
    .await;
    expect_client_abort(&mut rx, invoke_id, "the Error PDU mid-reassembly").await;

    let (mut client, result) = timeout(Duration::from_secs(2), task)
        .await
        .unwrap()
        .unwrap();
    match result {
        Err(Error::Abort { reason }) => {
            assert_eq!(reason, AbortReason::INVALID_APDU_IN_THIS_STATE.to_raw())
        }
        other => panic!("expected Err(Abort), got {other:?}"),
    }
    client.stop().await.unwrap();
}

/// A Reject PDU mid-reassembly takes the same UnexpectedPDU_Received path as
/// an Error — a separate arm in dispatch, so a separate test.
#[tokio::test]
async fn reject_pdu_mid_reassembly_aborts_the_transfer() {
    let (task, server, mut rx, invoke_id) = start_reassembly(ClientConfig::default()).await;

    send_to_client(&server, &response_segment(invoke_id, 0, true, &[0x01; 8])).await;
    expect_segment_ack(&mut rx, invoke_id, 0).await;

    send_to_client(
        &server,
        &Apdu::Reject(RejectPdu {
            invoke_id,
            reject_reason: RejectReason::UNRECOGNIZED_SERVICE,
        }),
    )
    .await;
    expect_client_abort(&mut rx, invoke_id, "the Reject PDU mid-reassembly").await;

    let (mut client, result) = timeout(Duration::from_secs(2), task)
        .await
        .unwrap()
        .unwrap();
    match result {
        Err(Error::Abort { reason }) => {
            assert_eq!(reason, AbortReason::INVALID_APDU_IN_THIS_STATE.to_raw())
        }
        other => panic!("expected Err(Abort), got {other:?}"),
    }
    client.stop().await.unwrap();
}

/// The guard order inside the Abort arm: an Abort with 'server' = FALSE — an
/// echo of this client's own — must NOT tear down the reassembly. Clause
/// 5.4.4.4 AbortPDU_Received fires only for 'server' = TRUE.
#[tokio::test]
async fn echoed_client_abort_does_not_end_the_session() {
    let (task, server, mut rx, invoke_id) = start_reassembly(ClientConfig::default()).await;

    send_to_client(&server, &response_segment(invoke_id, 0, true, &[0x01; 8])).await;
    expect_segment_ack(&mut rx, invoke_id, 0).await;

    send_to_client(
        &server,
        &Apdu::Abort(AbortPdu {
            sent_by_server: false,
            invoke_id,
            abort_reason: AbortReason::OTHER,
        }),
    )
    .await;

    send_to_client(&server, &response_segment(invoke_id, 1, false, &[0x02; 8])).await;
    expect_segment_ack(&mut rx, invoke_id, 1).await;

    let (mut client, result) = timeout(Duration::from_secs(2), task)
        .await
        .unwrap()
        .unwrap();
    let payload = result.expect("the transfer must survive an echoed client Abort");
    assert_eq!(&payload[..], &[[0x01u8; 8].as_slice(), &[0x02; 8]].concat());
    client.stop().await.unwrap();
}

/// The diversion is keyed on a live reassembly session ONLY: an ordinary
/// Error or Reject answering an unsegmented exchange must still surface as
/// itself. Guards against the diversion going unconditional.
#[tokio::test]
async fn error_and_reject_without_a_session_surface_as_themselves() {
    let (task, server, _rx, invoke_id) = start_reassembly(ClientConfig::default()).await;
    send_to_client(
        &server,
        &Apdu::Error(ErrorPdu {
            invoke_id,
            service_choice: ConfirmedServiceChoice::READ_PROPERTY,
            error_class: ErrorClass::PROPERTY,
            error_code: ErrorCode::UNKNOWN_PROPERTY,
            error_data: Bytes::new(),
        }),
    )
    .await;
    let (mut client, result) = timeout(Duration::from_secs(2), task)
        .await
        .unwrap()
        .unwrap();
    match result {
        Err(Error::Protocol { class, code }) => {
            assert_eq!(class, ErrorClass::PROPERTY.to_raw() as u32);
            assert_eq!(code, ErrorCode::UNKNOWN_PROPERTY.to_raw() as u32);
        }
        other => panic!("expected Err(Protocol), got {other:?}"),
    }
    client.stop().await.unwrap();

    let (task, server, _rx, invoke_id) = start_reassembly(ClientConfig::default()).await;
    send_to_client(
        &server,
        &Apdu::Reject(RejectPdu {
            invoke_id,
            reject_reason: RejectReason::BUFFER_OVERFLOW,
        }),
    )
    .await;
    let (mut client, result) = timeout(Duration::from_secs(2), task)
        .await
        .unwrap()
        .unwrap();
    match result {
        Err(Error::Reject { reason }) => {
            assert_eq!(reason, RejectReason::BUFFER_OVERFLOW.to_raw())
        }
        other => panic!("expected Err(Reject), got {other:?}"),
    }
    client.stop().await.unwrap();
}

/// The caller giving up is the fourth way a transaction ends. After
/// `cancel_transaction`, the next segment must find no pending transaction
/// and draw the 5.4.4.1 Abort. The reason assertion matters: a reaper
/// eviction would answer TSM_TIMEOUT, and the whole test stays far under the
/// reaper's 4 s so only the transaction gate can produce this Abort.
#[tokio::test]
async fn caller_timeout_ends_the_reassembly_session() {
    let config = ClientConfig {
        apdu_timeout_ms: 300,
        apdu_retries: 0,
        ..ClientConfig::default()
    };
    let (task, server, mut rx, invoke_id) = start_reassembly(config).await;

    send_to_client(&server, &response_segment(invoke_id, 0, true, &[0x01; 8])).await;
    expect_segment_ack(&mut rx, invoke_id, 0).await;

    // Past the caller's 300 ms timeout; it cancels the transaction. The
    // client itself stays up — the session must be ended by the transaction
    // gate, not by the client shutting down.
    let (mut client, result) = timeout(Duration::from_secs(2), task)
        .await
        .unwrap()
        .unwrap();
    match result {
        Err(Error::Timeout(_)) => {}
        other => panic!("expected Err(Timeout), got {other:?}"),
    }

    send_to_client(&server, &response_segment(invoke_id, 1, true, &[0x02; 8])).await;
    expect_client_abort(&mut rx, invoke_id, "a segment after the caller timed out").await;
    client.stop().await.unwrap();
}

/// A SimpleAck mid-reassembly is in the same Clause 5.4.4.4
/// UnexpectedPDU_Received list as Error and Reject: the segmented ComplexACK
/// under reassembly IS this transaction's answer, so a second answer aborts
/// the transfer rather than completing it.
#[tokio::test]
async fn simple_ack_mid_reassembly_aborts_the_transfer() {
    let (task, server, mut rx, invoke_id) = start_reassembly(ClientConfig::default()).await;

    send_to_client(&server, &response_segment(invoke_id, 0, true, &[0x01; 8])).await;
    expect_segment_ack(&mut rx, invoke_id, 0).await;

    send_to_client(
        &server,
        &Apdu::SimpleAck(bacnet_encoding::apdu::SimpleAck {
            invoke_id,
            service_choice: ConfirmedServiceChoice::READ_PROPERTY,
        }),
    )
    .await;
    expect_client_abort(&mut rx, invoke_id, "the SimpleAck mid-reassembly").await;

    let (mut client, result) = timeout(Duration::from_secs(2), task)
        .await
        .unwrap()
        .unwrap();
    match result {
        Err(Error::Abort { reason }) => {
            assert_eq!(reason, AbortReason::INVALID_APDU_IN_THIS_STATE.to_raw())
        }
        other => panic!("expected Err(Abort), got {other:?}"),
    }
    client.stop().await.unwrap();
}

/// "BACnet-ComplexACK-PDU with 'segmented-message' = FALSE" is also in the
/// Clause 5.4.4.4 UnexpectedPDU_Received list — it must not complete the
/// transaction with its own content while segments are outstanding.
#[tokio::test]
async fn unsegmented_complex_ack_mid_reassembly_aborts_the_transfer() {
    let (task, server, mut rx, invoke_id) = start_reassembly(ClientConfig::default()).await;

    send_to_client(&server, &response_segment(invoke_id, 0, true, &[0x01; 8])).await;
    expect_segment_ack(&mut rx, invoke_id, 0).await;

    send_to_client(
        &server,
        &Apdu::ComplexAck(ComplexAck {
            segmented: false,
            more_follows: false,
            invoke_id,
            sequence_number: None,
            proposed_window_size: None,
            service_choice: ConfirmedServiceChoice::READ_PROPERTY,
            service_ack: Bytes::from_static(&[0xEE; 4]),
        }),
    )
    .await;
    expect_client_abort(
        &mut rx,
        invoke_id,
        "the unsegmented ComplexAck mid-reassembly",
    )
    .await;

    let (mut client, result) = timeout(Duration::from_secs(2), task)
        .await
        .unwrap()
        .unwrap();
    match result {
        Err(Error::Abort { reason }) => {
            assert_eq!(reason, AbortReason::INVALID_APDU_IN_THIS_STATE.to_raw())
        }
        other => panic!("expected Err(Abort), got {other:?}"),
    }
    client.stop().await.unwrap();
}
