//! Local Number controls through actual MS/TP frames and application owners.
//! LoopbackSerial evidence only; no RS-485 timing or hardware qualification.
#[path = "mstp_network_numbers/support.rs"]
mod support;
use bacnet_encoding::{
    apdu::{decode_apdu, Apdu},
    npdu::decode_npdu,
};
use bacnet_transport::{mstp::MstpExecutionMode, mstp_frame::FrameType, port::TransportPort};
use support::*;

async fn controls(server: bool, mode: MstpExecutionMode) {
    let (mut owner, mut peer) = fixture(server, mode, Gates::new(false, false, false)).await;
    // An unknown owner and a unicast announcement cannot yield an earlier reply.
    // The first valid reply is a FIFO fence, not a timeout-based silence claim.
    peer.control(NODE, &[1, 0x80, 0x12]).await;
    peer.control(NODE, &[1, 0x80, 0x13, 0, 99, 1]).await;
    peer.control(BROADCAST, &[1, 0x80, 0x12]).await;
    peer.control(BROADCAST, &[1, 0x80, 0x13, 0, 77, 0]).await;
    peer.control(BROADCAST, &[1, 0x80, 0x12]).await;
    peer.number(77).await;
    peer.control(NODE, &[1, 0x80, 0x12]).await;
    peer.number(77).await;
    for (number, flag, expected) in [(78, 0, 78), (79, 1, 79), (80, 0, 79), (81, 1, 81)] {
        peer.control(BROADCAST, &[1, 0x80, 0x13, 0, number, flag])
            .await;
        peer.control(NODE, &[1, 0x80, 0x12]).await;
        peer.number(expected).await;
    }
    // Numeric/flag rejection is existing fail-closed policy, not a new mandate.
    for (destination, bad) in [
        (NODE, vec![1, 0x80, 0x13, 0, 99, 1]),
        (BROADCAST, vec![1, 0x80, 0x13, 0, 0, 1]),
        (BROADCAST, vec![1, 0x80, 0x13, 255, 255, 1]),
        (BROADCAST, vec![1, 0x80, 0x13, 0, 99, 2]),
        (BROADCAST, vec![1, 0x80, 0x13, 0, 99]),
        (BROADCAST, vec![1, 0x88, 0, 4, 1, 9, 0x13, 0, 99, 1]),
        (BROADCAST, vec![1, 0xa0, 255, 255, 0, 255, 0x13, 0, 99, 1]),
    ] {
        peer.control(destination, &bad).await;
        peer.control(NODE, &[1, 0x80, 0x12]).await;
        peer.number(81).await;
    }
    for (i, bad) in [
        vec![1, 0x80, 0x12, 0],
        vec![1, 0x88, 0, 4, 1, 9, 0x12],
        vec![1, 0xa0, 255, 255, 0, 255, 0x12],
    ]
    .iter()
    .enumerate()
    {
        peer.control(NODE, bad).await;
        let next = 82 + i as u8;
        peer.control(BROADCAST, &[1, 0x80, 0x13, 0, next, 1]).await;
        peer.control(NODE, &[1, 0x80, 0x12]).await;
        // An erroneous response to the earlier query would carry the old value.
        peer.number(next.into()).await;
    }
    bounded(owner.stop()).await;
}

async fn blocked_producer_progress(server: bool, mode: MstpExecutionMode) {
    let gates = Gates::new(true, false, false);
    let (mut owner, mut peer) = fixture(server, mode, gates.clone()).await;
    peer.control(BROADCAST, &[1, 0x80, 0x13, 0, 77, 1]).await;
    peer.control(NODE, &[1, 0x80, 0x12]).await;
    bounded(gates.queued.acquire()).await.unwrap().forget();
    // Drain the real queued frame; the producer stays held after enqueue, but
    // does not own the serial writer or MAC mutex, so application egress can run.
    peer.number(77).await;
    // Independent ReadProperty: analog-input 1 / present-value, Invoke ID 42.
    // NPDU version1/expecting-reply, confirmed unsegmented APDU, max-APDU480.
    let request = [1, 4, 0, 3, 42, 12, 0x0c, 0, 0, 0, 1, 0x19, 85];
    bounded(peer.frame(FrameType::BACnetDataExpectingReply, NODE, &request))
        .await
        .unwrap();
    let frame = peer.data().await;
    assert_eq!(frame.destination, PEER);
    let npdu = decode_npdu(frame.data).unwrap();
    assert!(!npdu.is_network_message);
    match decode_apdu(npdu.payload).unwrap() {
        Apdu::ComplexAck(ack) => {
            assert_eq!(ack.invoke_id, 42);
            assert_eq!(ack.service_choice.to_raw(), 12);
            // Encoded real value42.0 appears inside the returned property value.
            assert!(ack
                .service_ack
                .windows(5)
                .any(|bytes| bytes == [0x44, 0x42, 0x28, 0, 0]));
        }
        other => panic!("expected ReadProperty ACK, got {other:?}"),
    }
    assert_eq!(
        gates.send_dropped.available_permits(),
        0,
        "producer remains held during APDU progress"
    );
    bounded(owner.stop()).await;
    bounded(gates.send_dropped.acquire())
        .await
        .unwrap()
        .forget();
}

async fn stopped_producer(server: bool, mode: MstpExecutionMode, bare_drop: bool) {
    let gates = Gates::new(true, true, !bare_drop);
    let (mut owner, mut peer) = fixture(server, mode, gates.clone()).await;
    peer.control(BROADCAST, &[1, 0x80, 0x13, 0, 77, 0]).await;
    peer.control(NODE, &[1, 0x80, 0x12]).await;
    bounded(gates.queued.acquire()).await.unwrap().forget();
    // Actual queue admission happened. The optional serial gate also prevents
    // autonomous lost-token recovery from completing a number frame.
    if bare_drop {
        drop(owner);
    } else {
        {
            let stop = owner.stop();
            tokio::pin!(stop);
            bounded(async {
                tokio::select! {
                    _ = &mut stop => panic!("stop must wait for the transport gate"),
                    permit = gates.stop_started.acquire() => { permit.unwrap().forget(); }
                }
            })
            .await;
            // Drop this stop waiter while cleanup is known to be pending.
        }
        bounded(gates.send_dropped.acquire())
            .await
            .unwrap()
            .forget();
        gates.stop_release.add_permits(1);
        bounded(owner.stop()).await;
        drop(owner);
    }
    if bare_drop {
        bounded(gates.send_dropped.acquire())
            .await
            .unwrap()
            .forget();
    }
    peer.assert_released(&gates).await;
}

#[tokio::test]
async fn mstp_number_transport_group_and_any_delegation() {
    for mode in [MstpExecutionMode::Tokio, MstpExecutionMode::DedicatedThread] {
        let (mut transport, peer) = transport(mode, Gates::new(false, false, false)).await;
        assert!(transport.supports_local_nonrouter_number_controls());
        let mut received = transport.start().await.unwrap();
        for (destination, group) in [(NODE, false), (BROADCAST, true)] {
            let bytes = [1, 0x80, 0x13, 0, 77, 0];
            peer.control(destination, &bytes).await;
            let packet = bounded(received.recv()).await.unwrap();
            assert_eq!(packet.link_layer_group, group);
            assert_eq!(packet.source_mac.as_slice(), [PEER]);
            assert_eq!(packet.npdu.as_ref(), bytes);
        }
        bounded(transport.stop()).await.unwrap();
    }
}
macro_rules! mode_tests {
    ($name:ident, $server:expr, $mode:expr) => {
        #[tokio::test]
        async fn $name() {
            controls($server, $mode).await;
        }
    };
}
mode_tests!(
    mstp_number_server_tokio_wire,
    true,
    MstpExecutionMode::Tokio
);
mode_tests!(
    mstp_number_server_dedicated_wire,
    true,
    MstpExecutionMode::DedicatedThread
);
mode_tests!(
    mstp_number_endpoint_tokio_wire,
    false,
    MstpExecutionMode::Tokio
);
mode_tests!(
    mstp_number_endpoint_dedicated_wire,
    false,
    MstpExecutionMode::DedicatedThread
);
#[tokio::test]
async fn mstp_number_held_producer_preserves_application_progress() {
    for server in [true, false] {
        for mode in [MstpExecutionMode::Tokio, MstpExecutionMode::DedicatedThread] {
            blocked_producer_progress(server, mode).await;
        }
    }
}
#[tokio::test]
async fn mstp_number_queued_producer_canceled_stop_and_drop() {
    for server in [true, false] {
        for mode in [MstpExecutionMode::Tokio, MstpExecutionMode::DedicatedThread] {
            for bare_drop in [false, true] {
                stopped_producer(server, mode, bare_drop).await;
            }
        }
    }
}
