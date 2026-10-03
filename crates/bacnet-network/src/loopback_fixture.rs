//! Wire-level router fixtures shared by the loopback test modules
//! (`address_bound_tests`, `reject_route_tests`).
//!
//! Raw NPDU bytes go in through [`LoopbackTransport`] peers, and the frames
//! the router sends come back out of them, so a test sees exactly what a
//! neighbouring node would.

use bacnet_encoding::npdu::{
    decode_npdu, decode_reject_message_to_network, Npdu, NpduAddress, RejectMessageToNetwork,
};
use bacnet_transport::loopback::LoopbackTransport;
use bacnet_transport::port::{ReceivedNpdu, TransportPort};
use bacnet_types::enums::NetworkMessageType;
use bytes::Bytes;
use tokio::sync::mpsc;
use tokio::time::{timeout, Duration};

use crate::layer::{ReceivedApdu, ReceivedNetworkControl};
use crate::router::{BACnetRouter, RouterPort};

pub(crate) const APDU: [u8; 2] = [0x10, 0x08];
pub(crate) const TOO_LONG: u8 = NpduAddress::MAX_MAC_LEN as u8 + 1;
pub(crate) const LONGEST: u8 = NpduAddress::MAX_MAC_LEN as u8;
/// The original source network in routed frames.
pub(crate) const ORIGIN: u16 = 4000;
/// The network the fixture router reaches through peer B.
pub(crate) const REMOTE: u16 = 3000;

/// Hand-built NPDU bytes, since the encoder refuses the lengths under test.
/// `destination` is (DNET, DLEN) and `source` is (SNET, SLEN); each address
/// holds as many octets as its length announces. `control` makes it a network
/// message of that type carrying network 3000, in place of the APDU.
pub(crate) fn wire(
    destination: Option<(u16, u8)>,
    source: Option<(u16, u8)>,
    control: Option<u8>,
) -> Vec<u8> {
    let mut flags = 0;
    if control.is_some() {
        flags |= 0x80;
    }
    if destination.is_some() {
        flags |= 0x20;
    }
    if source.is_some() {
        flags |= 0x08;
    }
    let mut out = vec![0x01, flags];
    for ((network, length), first) in [(destination, 0xD0u8), (source, 0x50)]
        .into_iter()
        .filter_map(|(address, first)| address.map(|address| (address, first)))
    {
        out.extend_from_slice(&network.to_be_bytes());
        out.push(length);
        out.extend((0..length).map(|i| first.wrapping_add(i)));
    }
    if destination.is_some() {
        out.push(255);
    }
    match control {
        Some(message_type) => out.extend_from_slice(&[message_type, 0x0B, 0xB8]),
        None => out.extend_from_slice(&APDU),
    }
    out
}

pub(crate) async fn recv<T>(rx: &mut mpsc::Receiver<T>) -> T {
    timeout(Duration::from_secs(2), rx.recv())
        .await
        .expect("timed out waiting for the network layer")
        .expect("channel closed")
}

/// A two-port router with a loopback peer on each port.
pub(crate) struct RouterFixture {
    pub(crate) router: BACnetRouter,
    pub(crate) local: mpsc::Receiver<ReceivedApdu>,
    /// Peer on port 0 (network 1000), MAC 0x0A.
    pub(crate) peer_a: LoopbackTransport,
    pub(crate) from_router_a: mpsc::Receiver<ReceivedNpdu>,
    /// Peer on port 1 (network 2000), MAC 0x0B, the next hop to network 3000.
    pub(crate) peer_b: LoopbackTransport,
    pub(crate) from_router_b: mpsc::Receiver<ReceivedNpdu>,
}

impl RouterFixture {
    pub(crate) async fn start() -> Self {
        Self::launch(false).await.0
    }

    /// [`Self::start`], with the router's network-control receiver (#1175).
    pub(crate) async fn start_with_network_control(
    ) -> (Self, mpsc::Receiver<ReceivedNetworkControl>) {
        let (fixture, controls) = Self::launch(true).await;
        (fixture, controls.expect("opted in"))
    }

    async fn launch(
        network_control: bool,
    ) -> (Self, Option<mpsc::Receiver<ReceivedNetworkControl>>) {
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
        let (router, local, controls) = if network_control {
            let (router, local, controls) =
                BACnetRouter::start_with_network_control_receiver(ports)
                    .await
                    .unwrap();
            (router, local, Some(controls))
        } else {
            let (router, local) = BACnetRouter::start(ports).await.unwrap();
            (router, local, None)
        };
        let mut fixture = Self {
            router,
            local,
            peer_a,
            from_router_a,
            peer_b,
            from_router_b,
        };
        // Teach the router that network 3000 lies behind peer B. Its relay of
        // the announcement to port A shows the route is in place.
        let i_am = Some(NetworkMessageType::I_AM_ROUTER_TO_NETWORK.to_raw());
        fixture
            .peer_b
            .send_broadcast(&wire(None, None, i_am))
            .await
            .unwrap();
        loop {
            let frame = recv(&mut fixture.from_router_a).await;
            let npdu = decode_npdu(frame.npdu).unwrap();
            if npdu.message_type == i_am && npdu.payload[..] == REMOTE.to_be_bytes() {
                break;
            }
        }
        (fixture, controls)
    }

    pub(crate) async fn send_from_a(&self, bytes: &[u8]) {
        self.peer_a.send_unicast(bytes, &[0x01]).await.unwrap();
    }

    pub(crate) async fn send_from_b(&self, bytes: &[u8]) {
        self.peer_b.send_unicast(bytes, &[0x02]).await.unwrap();
    }

    pub(crate) async fn stop(mut self) {
        self.router.stop().await;
        self.peer_a.stop().await.unwrap();
        self.peer_b.stop().await.unwrap();
    }
}

/// The next frame a router sends to a peer, past its I-Am-Router-To-Network
/// announcements, as raw bytes with whether it went out as a data-link
/// broadcast.
pub(crate) async fn next_frame_from_router(rx: &mut mpsc::Receiver<ReceivedNpdu>) -> (Bytes, bool) {
    let i_am = Some(NetworkMessageType::I_AM_ROUTER_TO_NETWORK.to_raw());
    loop {
        let frame = recv(rx).await;
        if decode_npdu(frame.npdu.clone()).unwrap().message_type != i_am {
            return (frame.npdu, frame.link_layer_group);
        }
    }
}

/// [`next_frame_from_router`], decoded.
pub(crate) async fn next_from_router(rx: &mut mpsc::Receiver<ReceivedNpdu>) -> (Npdu, bool) {
    let (frame, broadcast) = next_frame_from_router(rx).await;
    (decode_npdu(frame).unwrap(), broadcast)
}

pub(crate) fn reject_of(npdu: &Npdu) -> RejectMessageToNetwork {
    assert_eq!(
        npdu.message_type,
        Some(NetworkMessageType::REJECT_MESSAGE_TO_NETWORK.to_raw())
    );
    decode_reject_message_to_network(&npdu.payload).unwrap()
}
