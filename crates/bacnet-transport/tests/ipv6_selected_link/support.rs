use super::wire;
use socket2::{Domain, Protocol, Socket, Type};
use std::{
    net::{Ipv6Addr, SocketAddrV6},
    time::Duration,
};
use tokio::net::UdpSocket;

pub(super) const GROUP: Ipv6Addr = Ipv6Addr::new(0xff05, 0, 0, 0, 0, 0, 0, 0xbac0);
pub(super) const NPDU: &[u8] = &[1, 0, 0x10, 0x08];
pub(super) const DEADLINE: Duration = Duration::from_secs(2);

pub(super) fn fixture() -> (Ipv6Addr, u32) {
    let address: Ipv6Addr = std::env::var("RB_IPV6_TEST_ADDRESS")
        .expect("run only on an explicitly supplied isolated IPv6 link")
        .parse()
        .unwrap();
    let index: u32 = std::env::var("RB_IPV6_TEST_INDEX")
        .expect("the isolated interface index must be supplied")
        .parse()
        .unwrap();
    assert!(
        address.is_unique_local()
            || (address.is_loopback()
                && std::env::var("RB_IPV6_LOOPBACK_ONLY").as_deref() == Ok("1")),
        "fixture requires an isolated ULA or explicit loopback-only mode"
    );
    assert_ne!(index, 0, "OS-default interface is not a selected link");
    (address, index)
}

pub(super) fn udp(address: Ipv6Addr, port: u16, index: u32, join: bool) -> UdpSocket {
    let socket = Socket::new(Domain::IPV6, Type::DGRAM, Some(Protocol::UDP)).unwrap();
    socket.set_only_v6(true).unwrap();
    wire::configure(&socket);
    socket.set_reuse_address(true).unwrap();
    socket.set_nonblocking(true).unwrap();
    socket.set_multicast_if_v6(index).unwrap();
    socket.set_multicast_loop_v6(true).unwrap();
    // The independent oracle never emits beyond this local link.
    socket.set_multicast_hops_v6(0).unwrap();
    socket
        .bind(&SocketAddrV6::new(address, port, 0, 0).into())
        .unwrap();
    if join {
        socket.join_multicast_v6(&GROUP, index).unwrap();
    }
    UdpSocket::from_std(socket.into()).unwrap()
}

pub(super) async fn wire_broadcast(
    socket: &UdpSocket,
    expected_npdu: &[u8],
) -> Result<wire::Frame, String> {
    tokio::time::timeout(DEADLINE, async {
        loop {
            let frame = wire::receive(socket).await.unwrap();
            if frame.bytes.len() >= 7
                && frame.bytes[..2] == [0x82, 0x02]
                && &frame.bytes[7..] == expected_npdu
            {
                return frame;
            }
        }
    })
    .await
    .map_err(|_| "no Original-Broadcast-NPDU observed on selected link".to_owned())
}
