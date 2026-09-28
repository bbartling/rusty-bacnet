//! Real TLS accepted sockets with an independently retained registered listener.
use super::*;
use crate::port::DirectResponseScope;

#[tokio::test]
async fn direct_response_registered_transport_stop_abort_drop_seal_retained_listener() {
    for mode in 0..3 {
        let ca = TestCa::generate();
        let (ws, hub) = crate::sc::LoopbackWebSocket::pair();
        let config = DirectAcceptConfig::new(
            loopback_addr(),
            LISTENER_VMAC,
            LISTENER_UUID,
            ca.node_config(vec!["localhost".into()]),
        );
        let (mut transport, mut listener) = ScTransport::new(ws, LISTENER_VMAC)
            .with_device_uuid(LISTENER_UUID)
            .with_direct_listener(config)
            .await
            .unwrap();
        let (started, ()) = tokio::join!(transport.start(), hub_accept(&hub, [0x33; 6]));
        let mut rx = started.unwrap();
        let (peer, mut connection) = dial_and_handshake(
            &direct_url(&listener.local_addr()),
            ca.node_config(vec!["peer".into()]),
        )
        .await;
        let mut bytes = BytesMut::new();
        encode_sc_message(
            &mut bytes,
            &connection
                .build_direct_encapsulated_npdu(NPDU, &[])
                .unwrap(),
        );
        peer.send(&bytes).await.unwrap();
        let ingress = tokio::time::timeout(Duration::from_secs(5), rx.recv())
            .await
            .unwrap()
            .unwrap();
        let route = ingress.direct_response.unwrap();
        let scope = DirectResponseScope::default();
        route.send(NPDU, &scope).await.unwrap();
        let reply = decode_sc_message(&peer.recv().await.unwrap()).unwrap();
        assert_eq!(reply.function, ScFunction::EncapsulatedNpdu);
        assert_eq!(reply.payload.as_ref(), NPDU);
        let mut queued = Box::pin(route.send(&[1, 0, 0x44], &scope));
        assert!(futures_util::poll!(&mut queued).is_pending());
        // Current-thread scheduling: queue exists, but the sole writer has not
        // polled it. Every teardown seals before its first possible yield.
        match mode {
            0 => {
                transport.stop().await.unwrap();
                transport.stop().await.unwrap();
            }
            1 => {
                transport.abort();
                transport.abort();
            }
            _ => drop(transport),
        }
        assert!(*listener.shutdown_status().borrow());
        listener.stop().await; // retained handle joins the shared teardown
        assert_eq!(listener.active_connections(), 0);
        assert!(listener.membership.current_generations().is_empty());
        assert!(queued.await.is_err());
        assert!(route.send(NPDU, &scope).await.is_err());
        assert!(
            peer.recv().await.is_err(),
            "queued response cannot pass teardown"
        );
        listener.stop().await;
    }
}
