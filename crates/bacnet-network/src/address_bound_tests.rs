//! Network-layer handling of an over-long DADR or SADR (#1141), on the wire.
//!
//! Raw NPDU bytes go in through a [`LoopbackTransport`] peer. The non-router
//! [`NetworkLayer`] drops and counts an NPDU whose DLEN or SLEN is past
//! [`NpduAddress::MAX_MAC_LEN`]; the router also refuses to forward or deliver
//! it, and rejects it with reason 6 when it names a specific DNET. Every case
//! runs once per address field, and a boundary-length NPDU sent right after
//! the refused one is the first thing to come out, which shows the refused one
//! went nowhere.

use bacnet_encoding::npdu::{
    decode_npdu, decode_reject_message_to_network, Npdu, NpduAddress, NpduAddressField,
    RejectMessageToNetwork,
};
use bacnet_transport::loopback::LoopbackTransport;
use bacnet_transport::port::{ReceivedNpdu, TransportPort};
use bacnet_types::enums::{NetworkMessageType, RejectMessageReason};
use tokio::sync::mpsc;
use tokio::time::{timeout, Duration};

use crate::layer::NetworkLayer;
use crate::router::{BACnetRouter, RouterPort};

const FIELDS: [NpduAddressField; 2] = [NpduAddressField::Destination, NpduAddressField::Source];
const APDU: [u8; 2] = [0x10, 0x08];
const TOO_LONG: u8 = NpduAddress::MAX_MAC_LEN as u8 + 1;
const LONGEST: u8 = NpduAddress::MAX_MAC_LEN as u8;
/// The original source network in routed frames.
const ORIGIN: u16 = 4000;

/// Hand-built NPDU bytes, since the encoder refuses the lengths under test.
/// `destination` is (DNET, DLEN) and `source` is (SNET, SLEN); each address
/// holds as many octets as its length announces. `control` makes it a network
/// message of that type carrying network 3000, in place of the APDU.
fn wire(destination: Option<(u16, u8)>, source: Option<(u16, u8)>, control: Option<u8>) -> Vec<u8> {
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

async fn recv<T>(rx: &mut mpsc::Receiver<T>) -> T {
    timeout(Duration::from_secs(2), rx.recv())
        .await
        .expect("timed out waiting for the network layer")
        .expect("channel closed")
}

fn address_of(npdu: &Npdu, field: NpduAddressField) -> &NpduAddress {
    match field {
        NpduAddressField::Destination => npdu.destination.as_ref(),
        NpduAddressField::Source => npdu.source.as_ref(),
    }
    .expect("NPDU carries the address under test")
}

/// A non-router frame: a global broadcast DNET with a `length`-octet DADR, or
/// a local NPDU with a `length`-octet SADR.
fn local_frame(field: NpduAddressField, length: u8, control: Option<u8>) -> Vec<u8> {
    match field {
        NpduAddressField::Destination => wire(Some((0xFFFF, length)), None, control),
        NpduAddressField::Source => wire(None, Some((ORIGIN, length)), control),
    }
}

#[tokio::test]
async fn non_router_drops_and_counts_an_over_long_address_in_either_field() {
    let (transport, mut peer) = LoopbackTransport::pair(vec![0x01], vec![0x02]);
    let mut network = NetworkLayer::new(transport);
    let mut controls = network.enable_network_control_receiver().unwrap();
    let mut apdus = network.start().await.unwrap();
    let control = Some(NetworkMessageType::I_AM_ROUTER_TO_NETWORK.to_raw());

    for field in FIELDS {
        for length in [TOO_LONG, 255] {
            peer.send_unicast(&local_frame(field, length, None), &[0x01])
                .await
                .unwrap();
            peer.send_unicast(&local_frame(field, length, control), &[0x01])
                .await
                .unwrap();
        }
        peer.send_unicast(&local_frame(field, LONGEST, None), &[0x01])
            .await
            .unwrap();
        peer.send_unicast(&local_frame(field, LONGEST, control), &[0x01])
            .await
            .unwrap();

        let apdu = recv(&mut apdus).await;
        assert_eq!(apdu.apdu, APDU[..], "{field}");
        if field == NpduAddressField::Source {
            let source = apdu.source_network.expect("routed source survives");
            assert_eq!(source.mac_address.len(), NpduAddress::MAX_MAC_LEN);
        }
        let received = recv(&mut controls).await;
        assert_eq!(
            address_of(&received.npdu, field).mac_address.len(),
            NpduAddress::MAX_MAC_LEN,
            "{field}"
        );
    }
    assert_eq!(network.address_length_drops(), 8);

    network.stop().await.unwrap();
    peer.stop().await.unwrap();
}

struct RouterFixture {
    router: BACnetRouter,
    local: mpsc::Receiver<crate::layer::ReceivedApdu>,
    /// Peer on port 0 (network 1000), MAC 0x0A.
    peer_a: LoopbackTransport,
    from_router_a: mpsc::Receiver<ReceivedNpdu>,
    /// Peer on port 1 (network 2000), MAC 0x0B, the next hop to network 3000.
    peer_b: LoopbackTransport,
    from_router_b: mpsc::Receiver<ReceivedNpdu>,
}

const REMOTE: u16 = 3000;

impl RouterFixture {
    async fn start() -> Self {
        let (port_a, mut peer_a) = LoopbackTransport::pair(vec![0x01], vec![0x0A]);
        let (port_b, mut peer_b) = LoopbackTransport::pair(vec![0x02], vec![0x0B]);
        let from_router_a = peer_a.start().await.unwrap();
        let from_router_b = peer_b.start().await.unwrap();
        let (router, local) = BACnetRouter::start(vec![
            RouterPort {
                transport: port_a,
                network_number: 1000,
            },
            RouterPort {
                transport: port_b,
                network_number: 2000,
            },
        ])
        .await
        .unwrap();
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
        fixture
    }

    async fn send_from_a(&self, bytes: &[u8]) {
        self.peer_a.send_unicast(bytes, &[0x01]).await.unwrap();
    }

    async fn stop(mut self) {
        self.router.stop().await;
        self.peer_a.stop().await.unwrap();
        self.peer_b.stop().await.unwrap();
    }
}

/// The next frame the router sends to a peer, past its I-Am-Router-To-Network
/// announcements, with whether it went out as a data-link broadcast.
async fn next_from_router(rx: &mut mpsc::Receiver<ReceivedNpdu>) -> (Npdu, bool) {
    let i_am = Some(NetworkMessageType::I_AM_ROUTER_TO_NETWORK.to_raw());
    loop {
        let frame = recv(rx).await;
        let npdu = decode_npdu(frame.npdu).unwrap();
        if npdu.message_type != i_am {
            return (npdu, frame.link_layer_group);
        }
    }
}

fn reject_of(npdu: &Npdu) -> RejectMessageToNetwork {
    assert_eq!(
        npdu.message_type,
        Some(NetworkMessageType::REJECT_MESSAGE_TO_NETWORK.to_raw())
    );
    decode_reject_message_to_network(&npdu.payload).unwrap()
}

/// A frame from peer A toward network 3000 whose `field` address is `length`
/// octets long.
fn routed_frame(field: NpduAddressField, length: u8) -> Vec<u8> {
    match field {
        NpduAddressField::Destination => wire(Some((REMOTE, length)), None, None),
        NpduAddressField::Source => wire(Some((REMOTE, 1)), Some((ORIGIN, length)), None),
    }
}

#[tokio::test]
async fn router_rejects_an_over_long_address_toward_a_dnet_with_reason_6() {
    for field in FIELDS {
        let mut fixture = RouterFixture::start().await;

        fixture.send_from_a(&routed_frame(field, TOO_LONG)).await;
        let (reject, broadcast) = next_from_router(&mut fixture.from_router_a).await;
        assert!(!broadcast, "{field}: the reject is a unicast to the sender");
        assert!(reject.destination.is_none() && reject.source.is_none());
        assert_eq!(
            reject_of(&reject),
            RejectMessageToNetwork {
                reason: RejectMessageReason::ADDRESSING_ERROR,
                dnet: REMOTE,
            },
            "{field}"
        );

        fixture.send_from_a(&routed_frame(field, LONGEST)).await;
        let (forwarded, _) = next_from_router(&mut fixture.from_router_b).await;
        assert_eq!(forwarded.payload, APDU[..], "{field}");
        assert_eq!(forwarded.destination.as_ref().unwrap().network, REMOTE);
        assert_eq!(
            address_of(&forwarded, field).mac_address.len(),
            NpduAddress::MAX_MAC_LEN,
            "{field}: the boundary address is forwarded intact"
        );
        assert_eq!(fixture.router.address_length_drops(), 1, "{field}");
        fixture.stop().await;
    }
}

#[tokio::test]
async fn router_drops_an_over_long_broadcast_or_local_npdu_without_a_reject() {
    let mut fixture = RouterFixture::start().await;
    let refused = [
        wire(Some((0xFFFF, TOO_LONG)), None, None),
        wire(Some((0xFFFF, 0)), Some((ORIGIN, TOO_LONG)), None),
        wire(None, Some((ORIGIN, 255)), None),
    ];
    for bytes in &refused {
        fixture.send_from_a(bytes).await;
    }

    // For an unknown DNET the router broadcasts its route query on port B and
    // rejects with reason 1 on port A. Each is the first frame on its port,
    // so none of the refused NPDUs drew a reject or was forwarded.
    fixture
        .send_from_a(&wire(Some((5000, 0)), None, None))
        .await;
    let (reject, _) = next_from_router(&mut fixture.from_router_a).await;
    assert_eq!(
        reject_of(&reject).reason,
        RejectMessageReason::NOT_DIRECTLY_CONNECTED
    );
    let (solicit, _) = next_from_router(&mut fixture.from_router_b).await;
    assert_eq!(
        solicit.message_type,
        Some(NetworkMessageType::WHO_IS_ROUTER_TO_NETWORK.to_raw())
    );

    // Nor was any delivered locally: the boundary NPDU is the first to arrive.
    fixture
        .send_from_a(&wire(None, Some((ORIGIN, LONGEST)), None))
        .await;
    let delivered = recv(&mut fixture.local).await;
    let source = delivered.source_network.expect("routed source survives");
    assert_eq!(source.mac_address.len(), NpduAddress::MAX_MAC_LEN);
    assert_eq!(fixture.router.address_length_drops(), refused.len() as u64);
    fixture.stop().await;
}
