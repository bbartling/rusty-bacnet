//! The routed peer's advertised Max APDU Length Accepted bounds the request.
//!
//! Clause 5.2.1.2 term (c) binds the remote peer's limit with no exemption
//! for a destination reached through a router, and the client records that
//! limit from the I-Am's 'Max APDU Length Accepted' parameter, keyed by the
//! SNET/SADR of the NPDU that carried it — so a routed request must honor it
//! exactly as a local request does (issue #362).
//!
//! Split from `tests.rs`, which is at the 700-LOC cap.

use std::time::Instant;

use bacnet_encoding::apdu::{self, Apdu, SegmentAck as SegmentAckPdu, SimpleAck};
use bacnet_encoding::npdu::decode_npdu;
use bacnet_transport::loopback::LoopbackTransport;
use bacnet_transport::port::TransportPort;
use bacnet_types::enums::{ConfirmedServiceChoice, ObjectType, Segmentation};
use bacnet_types::primitives::ObjectIdentifier;
use bacnet_types::MacAddr;
use tokio::time::{timeout, Duration};

use crate::discovery::DiscoveredDevice;

use super::tests::send_routed_response;
use super::BACnetClient;

fn routed_peer(
    max_apdu_length: u32,
    router_mac: &[u8],
    network: u16,
    mac: &[u8],
) -> DiscoveredDevice {
    DiscoveredDevice {
        object_identifier: ObjectIdentifier::new(ObjectType::DEVICE, 3003).unwrap(),
        mac_address: MacAddr::from_slice(router_mac),
        max_apdu_length,
        segmentation_supported: Segmentation::BOTH,
        max_segments_accepted: None,
        vendor_id: 42,
        last_seen: Instant::now(),
        source_network: Some(network),
        source_address: Some(MacAddr::from_slice(mac)),
    }
}

/// A routed peer advertising 128 on a 1476-octet transport forces
/// segmentation at 128 rather than the request going out whole.
#[tokio::test]
async fn routed_confirmed_request_honors_discovered_peer_max_apdu() {
    let client_mac = vec![0x01];
    let router_mac = vec![0x02];
    let remote_network = 100;
    let remote_mac = vec![0x03];
    let (client_transport, mut router_transport) =
        LoopbackTransport::pair(client_mac.clone(), router_mac.clone());
    let mut router_rx = router_transport.start().await.unwrap();

    // Local config and transport both allow 1476, so only the routed peer's
    // discovered limit of 128 can force segmentation of a 204-octet APDU.
    let mut client = BACnetClient::generic_builder()
        .transport(client_transport)
        .apdu_timeout_ms(2000)
        .max_apdu_length(1476)
        .build()
        .await
        .unwrap();

    client.device_table.lock().await.upsert(routed_peer(
        128,
        &router_mac,
        remote_network,
        &remote_mac,
    ));

    let service_data: Vec<u8> = (0..200u16).map(|i| i as u8).collect();
    let expected_data = service_data.clone();
    let router_mac_for_request = router_mac.clone();
    let remote_mac_for_request = remote_mac.clone();

    let request_task = tokio::spawn(async move {
        let result = client
            .confirmed_request_routed(
                &router_mac_for_request,
                remote_network,
                &remote_mac_for_request,
                ConfirmedServiceChoice::WRITE_PROPERTY,
                &service_data,
            )
            .await;
        client.stop().await.unwrap();
        result
    });

    let mut all_service_data = Vec::new();
    let invoke_id = loop {
        let received = timeout(Duration::from_secs(2), router_rx.recv())
            .await
            .expect("router timed out waiting for routed segment")
            .expect("router channel closed");

        let npdu = decode_npdu(received.npdu).unwrap();
        assert!(
            npdu.payload.len() <= 128,
            "APDU of {} octets exceeds the peer's advertised limit of 128",
            npdu.payload.len()
        );

        let decoded = apdu::decode_apdu(npdu.payload).unwrap();
        let Apdu::ConfirmedRequest(req) = decoded else {
            panic!("Expected ConfirmedRequest, got {:?}", decoded);
        };
        assert!(
            req.segmented,
            "request must segment at the routed peer's limit of 128, not go out whole"
        );
        let seq = req.sequence_number.unwrap();
        all_service_data.extend_from_slice(&req.service_request);

        let seg_ack = Apdu::SegmentAck(SegmentAckPdu {
            negative_ack: false,
            sent_by_server: true,
            invoke_id: req.invoke_id,
            sequence_number: seq,
            actual_window_size: 1,
        });
        send_routed_response(
            &router_transport,
            &client_mac,
            remote_network,
            &remote_mac,
            seg_ack,
        )
        .await;

        if !req.more_follows {
            break req.invoke_id;
        }
    };

    assert_eq!(all_service_data, expected_data);

    let ack = Apdu::SimpleAck(SimpleAck {
        invoke_id,
        service_choice: ConfirmedServiceChoice::WRITE_PROPERTY,
    });
    send_routed_response(
        &router_transport,
        &client_mac,
        remote_network,
        &remote_mac,
        ack,
    )
    .await;

    let result = request_task.await.unwrap();
    assert!(result.unwrap().is_empty());
    router_transport.stop().await.unwrap();
}

/// A routed peer advertising less than MinimumMessageSize is rejected with the
/// peer named as the binding term, and nothing goes on the wire.
#[tokio::test]
async fn routed_confirmed_request_rejects_subminimum_peer_limit() {
    let client_mac = vec![0x01];
    let router_mac = vec![0x02];
    let remote_network = 100;
    let remote_mac = vec![0x03];
    let (client_transport, mut router_transport) =
        LoopbackTransport::pair(client_mac, router_mac.clone());
    let mut router_rx = router_transport.start().await.unwrap();

    let mut client = BACnetClient::generic_builder()
        .transport(client_transport)
        .apdu_timeout_ms(2000)
        .build()
        .await
        .unwrap();

    client.device_table.lock().await.upsert(routed_peer(
        3,
        &router_mac,
        remote_network,
        &remote_mac,
    ));

    let err = client
        .confirmed_request_routed(
            &router_mac,
            remote_network,
            &remote_mac,
            ConfirmedServiceChoice::READ_PROPERTY,
            &[0x01],
        )
        .await
        .unwrap_err();
    assert!(
        err.to_string()
            .contains("peer's advertised Max APDU Length Accepted of 3"),
        "the routed peer is the binding term, got: {err}"
    );

    assert!(
        timeout(Duration::from_millis(50), router_rx.recv())
            .await
            .is_err(),
        "no frame may reach the router for a rejected request"
    );

    client.stop().await.unwrap();
    router_transport.stop().await.unwrap();
}
