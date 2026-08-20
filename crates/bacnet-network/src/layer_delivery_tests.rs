use super::*;
use bacnet_transport::bip::BipTransport;
use std::net::Ipv4Addr;
use tokio::time::{timeout, Duration};

#[test]
fn effective_group_delivery_respects_npdu_destination_precedence() {
    let remote_unicast = NpduAddress {
        network: 200,
        mac_address: MacAddr::from_slice(&[0x11]),
    };
    let remote_broadcast = NpduAddress {
        network: 200,
        mac_address: MacAddr::new(),
    };
    let global_broadcast = NpduAddress {
        network: 0xFFFF,
        mac_address: MacAddr::new(),
    };

    assert!(!is_group_delivery(false, None));
    assert!(is_group_delivery(true, None));
    assert!(!is_group_delivery(false, Some(&remote_unicast)));
    assert!(!is_group_delivery(true, Some(&remote_unicast)));
    assert!(is_group_delivery(false, Some(&remote_broadcast)));
    assert!(is_group_delivery(false, Some(&global_broadcast)));
}

#[tokio::test]
async fn send_receive_apdu_unicast_is_not_marked_as_group_delivery() {
    let transport_a = BipTransport::new(Ipv4Addr::LOCALHOST, 0, Ipv4Addr::BROADCAST);
    let transport_b = BipTransport::new(Ipv4Addr::LOCALHOST, 0, Ipv4Addr::BROADCAST);

    let mut net_a = NetworkLayer::new(transport_a);
    let mut net_b = NetworkLayer::new(transport_b);

    let _rx_a = net_a.start().await.unwrap();
    let mut rx_b = net_b.start().await.unwrap();
    let test_apdu = vec![0x10, 0x08];

    net_a
        .send_apdu(
            &test_apdu,
            net_b.local_mac(),
            false,
            NetworkPriority::NORMAL,
        )
        .await
        .unwrap();

    let received = timeout(Duration::from_secs(2), rx_b.recv())
        .await
        .expect("Timed out waiting for APDU")
        .expect("Channel closed");

    assert_eq!(received.apdu, test_apdu);
    assert_eq!(received.source_mac.as_slice(), net_a.local_mac());
    assert!(received.source_network.is_none());
    assert!(!received.is_group);

    net_a.stop().await.unwrap();
    net_b.stop().await.unwrap();
}
