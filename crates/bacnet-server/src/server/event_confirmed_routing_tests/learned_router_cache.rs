//! Observe cache boundaries through terminal dispatch and subsequent sends.

use super::*;

const ROUTER_B: &[u8] = &[10, 0, 0, 2, 0xBA, 0xC0];

async fn wait_for_frames(harness: &Harness, expected: usize) {
    tokio::time::timeout(Duration::from_secs(1), async {
        while harness.broadcast_frames().len() + harness.unicast_frames().len() < expected {
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("notification workers reach the recording transport");
    assert_eq!(
        harness.broadcast_frames().len() + harness.unicast_frames().len(),
        expected,
        "no extra attempts before the long retry deadline"
    );
}

#[tokio::test]
async fn admitted_routes_stop_at_64_but_existing_network_updates_at_capacity() {
    let harness = Harness::new(
        (1000..1065)
            .map(|network| destination_for(address_recipient(network, RECIPIENT), true))
            .collect(),
        60_000,
    )
    .await;
    harness.distribute().await;
    wait_for_frames(&harness, 65).await;
    assert!(harness.unicast_frames().is_empty());
    let mut first = harness.broadcast_frames();
    first.sort_by_key(|frame| decode_confirmed(frame).0.destination.unwrap().network);
    for frame in &first {
        let (npdu, request) = decode_confirmed(frame);
        assert!(
            harness
                .ack_routed(
                    ROUTER_A,
                    npdu.destination.unwrap().network,
                    RECIPIENT,
                    request.invoke_id,
                )
                .await
        );
    }
    assert_eq!(harness.notification_transactions.active_count(), 0);

    harness.distribute().await;
    wait_for_frames(&harness, 130).await;
    let unicasts = harness.unicast_frames();
    assert_eq!(unicasts.len(), 64, "exactly 64 admitted routes were cached");
    let broadcasts = harness.broadcast_frames();
    assert_eq!(broadcasts.len(), 66);
    let (uncached, request) = decode_confirmed(&broadcasts[65]);
    assert_eq!(uncached.destination.unwrap().network, 1064);
    for (router, frame) in &unicasts {
        assert_eq!(router.as_slice(), ROUTER_A);
        let (npdu, request) = decode_confirmed(frame);
        let network = npdu.destination.unwrap().network;
        // A valid terminal from another router replaces an existing DNET,
        // even though the preceding 64 admitted routes filled the cache.
        let responding_router = if network == 1000 { ROUTER_B } else { ROUTER_A };
        assert!(
            harness
                .ack_routed(responding_router, network, RECIPIENT, request.invoke_id)
                .await
        );
    }
    assert!(
        harness
            .ack_routed(ROUTER_B, 1064, RECIPIENT, request.invoke_id)
            .await
    );

    harness.distribute().await;
    wait_for_frames(&harness, 195).await;
    let unicasts = harness.unicast_frames();
    assert_eq!(unicasts.len(), 128);
    for (router, frame) in &unicasts[64..] {
        let (npdu, request) = decode_confirmed(frame);
        let destination = npdu.destination.unwrap();
        assert_eq!(destination.mac_address.as_slice(), RECIPIENT);
        let expected = if destination.network == 1000 {
            ROUTER_B
        } else {
            ROUTER_A
        };
        assert_eq!(
            router.as_slice(),
            expected,
            "cached next hop after capacity update"
        );
        assert!(
            harness
                .ack_routed(expected, destination.network, RECIPIENT, request.invoke_id)
                .await
        );
    }
    let broadcasts = harness.broadcast_frames();
    assert_eq!(broadcasts.len(), 67, "the 65th DNET still broadcasts");
    let (npdu, request) = decode_confirmed(&broadcasts[66]);
    assert_eq!(npdu.destination.unwrap().network, 1064);
    assert!(
        harness
            .ack_routed(ROUTER_B, 1064, RECIPIENT, request.invoke_id)
            .await
    );
    assert_eq!(harness.notification_transactions.active_count(), 0);
}

#[tokio::test]
async fn unmatched_routed_terminal_cannot_teach_or_replace_a_router() {
    let harness = Harness::new(
        vec![destination_for(address_recipient(1000, RECIPIENT), true)],
        60_000,
    )
    .await;
    assert!(!harness.ack_routed(ROUTER_B, 1000, RECIPIENT, 7).await);
    harness.distribute().await;
    wait_for_frames(&harness, 1).await;
    assert!(
        harness.unicast_frames().is_empty(),
        "unmatched response did not teach"
    );
    let (_, request) = decode_confirmed(&harness.broadcast_frames()[0]);
    assert!(
        harness
            .ack_routed(ROUTER_A, 1000, RECIPIENT, request.invoke_id)
            .await
    );
    assert!(
        !harness
            .ack_routed(ROUTER_B, 1000, RECIPIENT, request.invoke_id)
            .await
    );
    harness.distribute().await;
    wait_for_frames(&harness, 2).await;
    let unicasts = harness.unicast_frames();
    assert_eq!(unicasts.len(), 1);
    assert_eq!(
        unicasts[0].0.as_slice(),
        ROUTER_A,
        "late duplicate did not replace the router"
    );
    let (_, request) = decode_confirmed(&unicasts[0].1);
    assert!(
        harness
            .ack_routed(ROUTER_A, 1000, RECIPIENT, request.invoke_id)
            .await
    );
}

#[tokio::test]
async fn admitted_empty_router_or_routed_address_does_not_teach() {
    let harness = Harness::new(
        vec![destination_for(address_recipient(1000, RECIPIENT), true)],
        60_000,
    )
    .await;
    let (operation, receiver) = harness
        .notification_transactions
        .reserve(
            canonical_direct_peer(ROUTER_B),
            ConfirmedServiceChoice::CONFIRMED_EVENT_NOTIFICATION,
        )
        .unwrap();
    harness
        .dispatch_terminal(
            ROUTER_B,
            Some(NpduAddress {
                network: 1000,
                mac_address: MacAddr::new(),
            }),
            Apdu::SimpleAck(SimpleAck {
                invoke_id: operation.invoke_id(),
                service_choice: ConfirmedServiceChoice::CONFIRMED_EVENT_NOTIFICATION,
            }),
        )
        .await;
    assert_eq!(
        receiver.await.unwrap(),
        CovAckResult::Ack,
        "empty SADR uses ordinary direct admission"
    );
    drop(operation);
    harness.distribute().await;
    wait_for_frames(&harness, 1).await;
    assert!(
        harness.unicast_frames().is_empty(),
        "empty SADR cannot teach a DNET"
    );
    let (_, request) = decode_confirmed(&harness.broadcast_frames()[0]);
    assert!(
        harness
            .ack_routed(&[], 1000, RECIPIENT, request.invoke_id)
            .await
    );

    harness.distribute().await;
    wait_for_frames(&harness, 2).await;
    assert!(
        harness.unicast_frames().is_empty(),
        "empty immediate MAC cannot become a router"
    );
    let (_, request) = decode_confirmed(&harness.broadcast_frames()[1]);
    assert!(
        harness
            .ack_routed(ROUTER_A, 1000, RECIPIENT, request.invoke_id)
            .await
    );
    harness.distribute().await;
    wait_for_frames(&harness, 3).await;
    let unicasts = harness.unicast_frames();
    assert_eq!(unicasts.len(), 1, "a valid routed terminal still teaches");
    assert_eq!(unicasts[0].0.as_slice(), ROUTER_A);
    let (_, request) = decode_confirmed(&unicasts[0].1);
    assert!(
        harness
            .ack_routed(ROUTER_A, 1000, RECIPIENT, request.invoke_id)
            .await
    );
}
