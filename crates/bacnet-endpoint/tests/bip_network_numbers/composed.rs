//! Both roles make progress during live Number controls on the same UDP owner.
use super::*;
use bacnet_types::{
    enums::{ObjectType, PropertyIdentifier},
    primitives::ObjectIdentifier,
};

#[tokio::test]
async fn endpoint_number_bbmd_both_roles_progress_stop_and_drop() {
    for bare_drop in [false, true] {
        let (mut endpoint, local) =
            start(builder().role(SessionRole::Both).enable_bbmd(vec![])).await;
        let observer = observer(local.port());
        let query_peer = udp().await;
        let responder_peer = udp().await;
        let requester_peer = udp().await;
        assert!(endpoint.server().is_some());
        let client = endpoint.cloned_client_handle().unwrap();
        let server = endpoint.cloned_server_handle().unwrap();
        let group = SocketAddrV4::new(BROADCAST, local.port());
        send(&query_peer, group, &frame(0x0b, &number(77, 1))).await;
        send(&query_peer, local, &frame(0x0a, QUERY)).await;
        expect_number(&observer, local, 0x0b, 77).await;
        let mut peer_mac = address(&responder_peer).ip().octets().to_vec();
        peer_mac.extend_from_slice(&address(&responder_peer).port().to_be_bytes());
        let request = client.read_property(
            &peer_mac,
            ObjectIdentifier::new(ObjectType::ANALOG_INPUT, 1).unwrap(),
            PropertyIdentifier::PRESENT_VALUE,
            None,
        );
        tokio::pin!(request);
        let wire = bounded(async {
            tokio::select! {
                result = &mut request => panic!("request completed without peer ACK: {result:?}"),
                packet = receive(&responder_peer) => packet,
            }
        })
        .await;
        assert_eq!(wire.1, local);
        assert_eq!(wire.0[1], 0x0a);
        let npdu = &wire.0[4..];
        assert_eq!(&npdu[..3], &[1, 4, 0]);
        assert_eq!(npdu[5], 12);
        assert_eq!(&npdu[6..], &[0x0c, 0, 0, 0, 1, 0x19, 85]);
        let outbound_id = npdu[4];
        // Independent inbound request while the outbound transaction awaits its
        // peer. Number replies remain live; no blocked physical writer is used.
        let inbound = [1, 4, 0, 5, 42, 12, 0x0c, 0, 0, 0, 1, 0x19, 85];
        send(&requester_peer, local, &frame(0x0a, &inbound)).await;
        send(&query_peer, local, &frame(0x0a, QUERY)).await;
        expect_number(&observer, local, 0x0b, 77).await;
        let mut ack = vec![
            1, 0, 0x30, 42, 12, 0x0c, 0, 0, 0, 1, 0x19, 85, 0x3e, 0x44, 0x42, 0x28, 0, 0, 0x3f,
        ];
        let (response, source) = receive(&requester_peer).await;
        assert_eq!(source, local);
        assert_eq!(response, frame(0x0a, &ack));
        ack[3] = outbound_id;
        send(&responder_peer, local, &frame(0x0a, &ack)).await;
        let result = bounded(&mut request).await.unwrap();
        assert_eq!(result.property_value, [0x44, 0x42, 0x28, 0, 0]);
        assert_eq!(endpoint.active_leases(), 0);
        if !bare_drop {
            bounded(endpoint.stop()).await.unwrap();
        }
        drop(endpoint);
        assert!(!server.is_session_alive());
        drop(observer); // remove independent shared bind before exclusive proof
        let rebound = bounded(async {
            loop {
                if let Ok(socket) = std::net::UdpSocket::bind(local) {
                    break socket;
                }
                tokio::task::yield_now().await;
            }
        })
        .await;
        drop(rebound);
        assert!(client
            .read_property(
                &peer_mac,
                ObjectIdentifier::new(ObjectType::ANALOG_INPUT, 1).unwrap(),
                PropertyIdentifier::PRESENT_VALUE,
                None
            )
            .await
            .is_err());
    }
}
