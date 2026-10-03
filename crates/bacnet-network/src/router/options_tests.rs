//! [`BACnetRouter::start`] over loopback ports with every option on, and
//! with none (#1220).

use std::sync::Arc;

use bacnet_transport::loopback::LoopbackTransport;
use bacnet_transport::port::{ReceivedNpdu, TransportPort};
use bacnet_types::enums::NetworkMessageType;
use tokio::time::{timeout, Duration};

use super::*;
use crate::loopback_fixture::recv;
use crate::router::RouterPort;

/// I-Am-Router-To-Network for 3000, as peer B announces it.
const I_AM_3000: [u8; 5] = [0x01, 0x80, 0x01, 0x0B, 0xB8];

/// Loopback peers A (0A, network 1000) and B (0B, network 2000), started,
/// and the router ports they face: the router is 01 and 02.
async fn ports() -> (
    Vec<RouterPort<LoopbackTransport>>,
    [(LoopbackTransport, mpsc::Receiver<ReceivedNpdu>); 2],
) {
    let (port_a, mut peer_a) = LoopbackTransport::pair(vec![0x01], vec![0x0A]);
    let (port_b, mut peer_b) = LoopbackTransport::pair(vec![0x02], vec![0x0B]);
    let from_router_a = peer_a.start().await.unwrap();
    let from_router_b = peer_b.start().await.unwrap();
    let ports = vec![
        RouterPort {
            transport: port_a,
            network_number: 1000,
        },
        RouterPort {
            transport: port_b,
            network_number: 2000,
        },
    ];
    (ports, [(peer_a, from_router_a), (peer_b, from_router_b)])
}

#[tokio::test]
async fn one_start_combines_admission_tracking_a_control_policy_and_the_control_receiver() {
    let (ports, [(mut peer_a, _), (mut peer_b, _)]) = ports().await;
    // Hardened, with an authorizer that admits rejects and nothing else.
    let reject = NetworkMessageType::REJECT_MESSAGE_TO_NETWORK.to_raw();
    let options = RouterOptions::new()
        .track_admission()
        .control_policy(ControlPolicy::Hardened)
        .control_authorizer(Arc::new(move |ctx| ctx.message_type == reject))
        .network_control_receiver();
    let StartedRouter {
        mut router,
        mut apdus,
        network_control,
    } = BACnetRouter::start(ports, options).await.unwrap();
    let mut controls = network_control.expect("asked for");
    let counters = apdus.counters();

    // Peer B announces 3000, which the authorizer refuses, then sends the
    // router a reject (no DNET, reason 1 for 3000), which it admits. One
    // dispatch task handles both, in order.
    peer_b.send_broadcast(&I_AM_3000).await.unwrap();
    let reject_3000 = [0x01, 0x80, 0x03, 0x01, 0x0B, 0xB8];
    peer_b.send_unicast(&reject_3000, &[0x02]).await.unwrap();
    let control = recv(&mut controls).await;
    assert_eq!(control.npdu.payload[..], reject_3000[3..]);
    assert_eq!(control.source_mac.as_slice(), [0x0B]);
    let decisions = router.control_snapshot();
    assert_eq!(
        (decisions.i_am.allow_total, decisions.i_am.deny_total),
        (0, 1)
    );
    assert_eq!(decisions.reject.allow_total, 1);
    assert!(router.table().lock().await.lookup(3000).is_none());

    // A local APDU from peer A lands in the tracked queue, which counts it.
    peer_a
        .send_unicast(&[0x01, 0x00, 0x10, 0x08], &[0x01])
        .await
        .unwrap();
    let apdu = timeout(Duration::from_secs(2), apdus.recv())
        .await
        .expect("local APDU")
        .expect("queue open");
    assert_eq!(apdu.apdu[..], [0x10, 0x08]);
    assert_eq!(apdu.ingress_network, Some(1000));
    let snapshot = counters.snapshot();
    assert_eq!((snapshot.current_depth, snapshot.high_water), (0, 1));

    router.stop().await;
    peer_a.stop().await.unwrap();
    peer_b.stop().await.unwrap();
}

#[tokio::test]
async fn plain_options_start_a_permissive_router_without_a_control_receiver() {
    let (ports, [(mut peer_a, mut from_router_a), (mut peer_b, _)]) = ports().await;
    let StartedRouter {
        mut router,
        apdus: _apdus,
        network_control,
    } = BACnetRouter::start(ports, RouterOptions::new())
        .await
        .unwrap();
    assert!(network_control.is_none());

    // The permissive policy admits peer B's I-Am: the router learns 3000 and
    // passes the announcement on to port A.
    peer_b.send_broadcast(&I_AM_3000).await.unwrap();
    loop {
        let frame = recv(&mut from_router_a).await;
        if frame.npdu[..] == I_AM_3000 {
            break;
        }
    }
    assert_eq!(router.control_snapshot().i_am.allow_total, 1);
    assert_eq!(
        router.table().lock().await.lookup(3000).unwrap().port_index,
        1
    );

    router.stop().await;
    peer_a.stop().await.unwrap();
    peer_b.stop().await.unwrap();
}
