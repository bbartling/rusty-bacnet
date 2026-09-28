//! Network/server lifetime and router propagation over real TLS ingress.
use super::*;
use bacnet_network::response_route::ResponseRoute;

fn idle_network() -> NetworkLayer<QueuedPort> {
    let (_, incoming) = mpsc::channel(1);
    let (responses, _) = mpsc::unbounded_channel();
    NetworkLayer::new(QueuedPort {
        incoming: Some(incoming),
        responses,
    })
}
async fn issue(
    net: &NetworkLayer<QueuedPort>,
    route: &ResponseRoute,
    invoke: u8,
) -> Result<(), Error> {
    net.send_response_apdu_on_issuance(
        &[0x20, invoke, 15],
        &PEER_MAC,
        None,
        false,
        NetworkPriority::NORMAL,
        route,
        || {},
    )
    .await
}

#[tokio::test]
async fn direct_response_network_stop_and_server_drop_seal_retained_routes() {
    let ca = TestCa::new();
    let mut f = Fixture::new(
        &ca,
        ServerConfig::default(),
        database(Arc::new(AtomicUsize::new(0))),
    )
    .await;
    let mut a = f.peer(ca.tls("a")).await;
    let envelope = f.capture(&mut a, &read_name(11)).await;
    let route = ResponseRoute::new(envelope.provenance, envelope.direct_response.clone());
    let mut net = idle_network();
    issue(&net, &route, 11).await.unwrap();
    assert!(matches!(f.response().await, Apdu::SimpleAck(ack) if ack.invoke_id == 11));
    net.stop().await.unwrap();
    net.stop().await.unwrap();
    assert!(issue(&net, &route, 12).await.is_err());
    // Keep the network allocation alive deliberately: Drop must seal before
    // asynchronous request cancellation or the final Arc release.
    let network = f.server.network.as_ref().unwrap().clone();
    let mut queued = Box::pin(issue(&network, &route, 13));
    assert!(futures_util::poll!(&mut queued).is_pending());
    drop(f.server);
    assert!(queued.await.is_err());
    assert!(issue(&network, &route, 14).await.is_err());
    // The standalone listener remains independently owned; stop supplies EOF
    // as a deterministic boundary proving no queued application frame escaped.
    f.listener.stop().await;
    assert!(a.ws.recv().await.is_err());
    assert!(f.responses.try_recv().is_err());
}

#[tokio::test]
async fn direct_response_server_stop_cancels_held_request_and_keeps_listener_handle_explicit() {
    let ca = TestCa::new();
    let mut f = Fixture::new(
        &ca,
        ServerConfig::default(),
        database(Arc::new(AtomicUsize::new(0))),
    )
    .await;
    let mut a = f.peer(ca.tls("a")).await;
    let live = f.capture(&mut a, &read_name(20)).await;
    f.feed(live).await;
    assert_name(socket_response(&mut f, &a).await, 20);
    f.active(0).await;
    let db = f.server.db.clone();
    let held = db.write().await;
    let waiting = f.capture(&mut a, &read_name(21)).await;
    f.feed(waiting).await;
    f.active(1).await;
    bounded(f.server.stop()).await.unwrap();
    f.server.stop().await.unwrap();
    drop(held);
    assert_eq!(f.server.request_tasks.counters().confirmed_active, 0);
    assert!(f.server.seg_ack_senders.lock().is_empty());
    f.listener.stop().await;
    assert!(a.ws.recv().await.is_err());
    assert!(f.responses.try_recv().is_err());
}

#[tokio::test]
async fn direct_response_router_local_delivery_preserves_matching_capability() {
    use bacnet_network::router::{BACnetRouter, RouterPort};
    let ca = TestCa::new();
    let mut f = Fixture::new(
        &ca,
        ServerConfig::default(),
        database(Arc::new(AtomicUsize::new(0))),
    )
    .await;
    let mut a = f.peer(ca.tls("a")).await;
    let (tx, incoming) = mpsc::channel(8);
    let (responses, mut generic) = mpsc::unbounded_channel();
    let (mut router, mut local) = BACnetRouter::start(vec![RouterPort {
        transport: QueuedPort {
            incoming: Some(incoming),
            responses,
        },
        network_number: 44,
    }])
    .await
    .unwrap();
    for (invoke, destination) in [
        (1, None),
        (
            2,
            Some(NpduAddress {
                network: 44,
                mac_address: MacAddr::from_slice(&[0xaa; 6]),
            }),
        ),
    ] {
        let mut envelope = f.capture(&mut a, &read_name(invoke)).await;
        let expected = envelope.provenance;
        let mut npdu = decode_npdu(envelope.npdu).unwrap();
        npdu.destination = destination;
        let mut bytes = BytesMut::new();
        encode_npdu(&mut bytes, &npdu).unwrap();
        envelope.npdu = bytes.freeze();
        tx.send(envelope).await.unwrap();
        let received = bounded(local.recv()).await.unwrap();
        assert_eq!(received.provenance, expected);
        assert_eq!(
            received.direct_response.as_ref().unwrap().identity(),
            expected.direct_sc_identity().unwrap()
        );
        issue(
            f.server.network.as_ref().unwrap(),
            &received.response_route(),
            invoke,
        )
        .await
        .unwrap();
        assert!(matches!(f.response().await, Apdu::SimpleAck(ack) if ack.invoke_id == invoke));
    }
    assert!(generic.try_recv().is_err());
    router.stop().await;
    f.stop().await;
}
