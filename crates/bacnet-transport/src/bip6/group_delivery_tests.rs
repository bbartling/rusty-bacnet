//! An Original-Unicast-NPDU that was sent to a B/IPv6 multicast group is never
//! handed up as a directed NPDU (#1301). The receive path drops it, and the
//! NPDU's `link_layer_group` follows the address as well as the function.
//! Datagrams are fed in-process with the destination the OS would report.

use std::net::{IpAddr, Ipv6Addr, SocketAddr, SocketAddrV6};
use std::sync::Arc;

use bytes::BytesMut;
use tokio::sync::mpsc;

use super::receive::Receiver;
use super::socket::Bip6Socket;
use super::vmac_table::VmacTable;
use super::*;
use crate::port::ReceivedNpdu;
use crate::port::TransportPort;
use crate::udp_metadata::ReceivedDatagram;

/// A ReadProperty confirmed request in an NPDU that expects a reply.
const CONFIRMED_REQUEST: &[u8] = &[
    0x01, 0x04, 0x00, 0x05, 0x01, 0x0C, 0x0C, 0x02, 0x00, 0x00, 0x01, 0x19, 0x55,
];
const LOCAL_VMAC: Bip6Vmac = [0x00, 0x05, 0x15];
const SENDER_VMAC: Bip6Vmac = [0x00, 0x05, 0x1E];

fn local_ip() -> Ipv6Addr {
    Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 0x10)
}

fn sender() -> SocketAddrV6 {
    SocketAddrV6::new(
        Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 0x30),
        0xBAC0,
        0,
        0,
    )
}

/// A receiver bound in-process to `2001:db8::10` whose only listener is the
/// returned NPDU channel. The socket is only used for address-resolution
/// replies, which these tests never draw.
async fn receiver() -> (Receiver, mpsc::Receiver<ReceivedNpdu>) {
    let socket = Bip6Socket::bind(Ipv6Addr::LOCALHOST, 0, None)
        .await
        .unwrap();
    let (tx, rx) = mpsc::channel(4);
    let receiver = Receiver {
        socket: Arc::new(socket),
        tx,
        local_mac: encode_bip6_mac(local_ip(), 0xBAC0),
        vmac: LOCAL_VMAC,
        local_ip: local_ip(),
        unicast_ips: vec![local_ip()],
        wildcard_bind: false,
        foreign_bbmd: None,
        vmac_table: VmacTable::new(),
        forwarded_group_origin_drops: Arc::default(),
    };
    (receiver, rx)
}

fn original_unicast() -> BytesMut {
    original_unicast_to(LOCAL_VMAC)
}

fn original_unicast_to(destination_vmac: Bip6Vmac) -> BytesMut {
    let mut buf = BytesMut::new();
    encode_bvlc6_original_unicast(&mut buf, &SENDER_VMAC, &destination_vmac, CONFIRMED_REQUEST)
        .unwrap();
    buf
}

fn original_broadcast() -> BytesMut {
    let mut buf = BytesMut::new();
    encode_bvlc6_original_broadcast(&mut buf, &SENDER_VMAC, CONFIRMED_REQUEST).unwrap();
    buf
}

fn datagram(
    data: &[u8],
    destination: Ipv6Addr,
    os_group_delivery: Option<bool>,
) -> ReceivedDatagram {
    ReceivedDatagram {
        len: data.len(),
        peer: SocketAddr::V6(sender()),
        destination: IpAddr::V6(destination),
        arrival_index: Some(1),
        os_group_delivery,
    }
}

#[tokio::test]
async fn original_unicast_sent_to_a_multicast_group_is_dropped() {
    let (receiver, mut rx) = receiver().await;
    let unicast = original_unicast();

    // Each BACnet multicast scope, and a datagram to this node's own address
    // that Windows flags as a group delivery.
    for (destination, os) in [
        (BACNET_IPV6_MULTICAST_LINK_LOCAL, None),
        (BACNET_IPV6_MULTICAST_SITE_LOCAL, None),
        (BACNET_IPV6_MULTICAST_ORG_LOCAL, None),
        (local_ip(), Some(true)),
    ] {
        receiver
            .handle_datagram(&unicast, &datagram(&unicast, destination, os))
            .await;
        assert!(rx.try_recv().is_err(), "{destination} {os:?}");
    }

    receiver
        .handle_datagram(&unicast, &datagram(&unicast, local_ip(), None))
        .await;
    let directed = rx
        .try_recv()
        .expect("a directed Original-Unicast-NPDU is handed up");
    assert_eq!(directed.npdu.as_ref(), CONFIRMED_REQUEST);
    assert!(!directed.link_layer_group);

    let broadcast = original_broadcast();
    receiver
        .handle_datagram(
            &broadcast,
            &datagram(&broadcast, BACNET_IPV6_MULTICAST_LINK_LOCAL, None),
        )
        .await;
    let group = rx
        .try_recv()
        .expect("an Original-Broadcast-NPDU to the group is handed up");
    assert!(group.link_layer_group);
}

#[tokio::test]
async fn original_unicast_takes_its_group_flag_from_the_destination() {
    let (receiver, mut rx) = receiver().await;
    let unicast = original_unicast();
    for (destination, os, group) in [
        (BACNET_IPV6_MULTICAST_LINK_LOCAL, None, true),
        (local_ip(), Some(true), true),
        (local_ip(), None, false),
    ] {
        let frame = decode_bvlc6(&unicast).unwrap();
        receiver
            .dispatch(frame, &datagram(&unicast, destination, os))
            .await;
        let npdu = rx.try_recv().expect("dispatch hands the NPDU up");
        assert_eq!(npdu.link_layer_group, group, "{destination} {os:?}");
    }
}

/// A directed frame that names another node's virtual address is dropped,
/// even at this node's own unicast address (U.3).
#[tokio::test]
async fn original_unicast_for_another_vmac_is_dropped() {
    let (receiver, mut rx) = receiver().await;
    let other = original_unicast_to([0x00, 0x05, 0x16]);
    receiver
        .handle_datagram(&other, &datagram(&other, local_ip(), None))
        .await;
    assert!(rx.try_recv().is_err());

    let ours = original_unicast();
    receiver
        .handle_datagram(&ours, &datagram(&ours, local_ip(), None))
        .await;
    assert!(
        rx.try_recv().is_ok(),
        "the same frame for this VMAC is handed up"
    );
}

/// #1479: every IPv6 multicast group is a group destination at any port,
/// the BACnet groups and others such as ff02::1, while `is_broadcast_mac`
/// keeps to the BACnet groups. The owned rule agrees with the live one.
#[test]
fn every_multicast_group_is_a_group_destination() {
    let transport = Bip6Transport::new(Ipv6Addr::LOCALHOST, 0xBAC0, None);
    let owned = transport.group_destinations();
    let mac = |ip: Ipv6Addr, port: u16| [&ip.octets()[..], &port.to_be_bytes()].concat();
    for (ip, group) in [
        (BACNET_IPV6_MULTICAST_LINK_LOCAL, true),
        ("ff02::1".parse().unwrap(), true),
        ("ff05::1:3".parse().unwrap(), true),
        ("fe80::1".parse().unwrap(), false),
        ("2001:db8::7".parse().unwrap(), false),
        (Ipv6Addr::LOCALHOST, false),
    ] {
        for port in [0xBAC0, 0x1234] {
            assert_eq!(
                transport.is_group_destination(&mac(ip, port)),
                group,
                "{ip}"
            );
            assert_eq!(owned.contains(&mac(ip, port)), group, "{ip}");
        }
    }
    assert!(!transport.is_broadcast_mac(&mac("ff02::1".parse().unwrap(), 0xBAC0)));
    assert!(!transport.is_group_destination(&[0xFF; 16]));
}

/// A Forwarded-NPDU from `origin`, carrying a ReadProperty request.
fn forwarded_from(origin: SocketAddrV6) -> BytesMut {
    let mut payload = origin.ip().octets().to_vec();
    payload.extend_from_slice(&origin.port().to_be_bytes());
    payload.extend_from_slice(CONFIRMED_REQUEST);
    let mut buf = BytesMut::new();
    encode_bvlc6(
        &mut buf,
        Bvlc6Function::ForwardedNpdu,
        &SENDER_VMAC,
        &payload,
    )
    .unwrap();
    buf
}

/// #1493: the original source of a Forwarded-NPDU becomes the NPDU's source,
/// so one that is a multicast group, a group destination at any port, makes
/// the frame malformed. It is dropped and counted, and never handed up; one
/// from a node's own address still is.
#[tokio::test]
async fn a_forwarded_npdu_from_a_multicast_origin_is_dropped_and_counted() {
    let (receiver, mut rx) = receiver().await;
    let origins: [(Ipv6Addr, u16); 3] = [
        (BACNET_IPV6_MULTICAST_SITE_LOCAL, 0xBAC0),
        ("ff02::1".parse().unwrap(), 0xBAC0),
        ("ff0e::1:3".parse().unwrap(), 0x1234),
    ];
    for (ip, port) in origins {
        let frame = forwarded_from(SocketAddrV6::new(ip, port, 0, 0));
        receiver
            .handle_datagram(
                &frame,
                &datagram(&frame, BACNET_IPV6_MULTICAST_SITE_LOCAL, None),
            )
            .await;
        assert!(rx.try_recv().is_err(), "{ip}");
    }
    assert_eq!(
        receiver
            .forwarded_group_origin_drops
            .load(std::sync::atomic::Ordering::Relaxed),
        origins.len() as u64
    );

    let station = SocketAddrV6::new("2001:db8::20".parse().unwrap(), 0xBAC0, 0, 0);
    let frame = forwarded_from(station);
    receiver
        .handle_datagram(
            &frame,
            &datagram(&frame, BACNET_IPV6_MULTICAST_SITE_LOCAL, None),
        )
        .await;
    let npdu = rx.try_recv().expect("a unicast origin is handed up");
    assert_eq!(
        npdu.source_mac.as_slice(),
        &encode_bip6_mac(*station.ip(), station.port())
    );
}

/// The transport reports the receiver's count.
#[tokio::test]
async fn a_running_transport_counts_multicast_origins() {
    let bbmd = tokio::net::UdpSocket::bind("[::1]:0").await.unwrap();
    let SocketAddr::V6(bbmd_addr) = bbmd.local_addr().unwrap() else {
        unreachable!()
    };
    let mut transport = Bip6Transport::new(Ipv6Addr::LOCALHOST, 0, Some(45));
    transport.register_as_foreign_device(Bip6ForeignDeviceConfig {
        bbmd_ip: *bbmd_addr.ip(),
        bbmd_port: bbmd_addr.port(),
        ttl: 60,
    });
    let mut rx = transport.start().await.unwrap();
    let (_, port) = decode_bip6_mac(transport.local_mac()).unwrap();
    let to = SocketAddrV6::new(Ipv6Addr::LOCALHOST, port, 0, 0);
    let station = SocketAddrV6::new("2001:db8::20".parse().unwrap(), 0xBAC0, 0, 0);
    let group = SocketAddrV6::new("ff02::1".parse().unwrap(), 0xBAC0, 0, 0);
    for origin in [group, station] {
        bbmd.send_to(&forwarded_from(origin), to).await.unwrap();
    }
    let received = tokio::time::timeout(std::time::Duration::from_secs(2), rx.recv())
        .await
        .expect("the station's frame arrives")
        .unwrap();
    assert_eq!(
        received.source_mac.as_slice(),
        &encode_bip6_mac(*station.ip(), station.port()),
        "the group origin went nowhere"
    );
    assert_eq!(transport.forwarded_group_origin_drops(), 1);
    transport.stop().await.unwrap();
}
