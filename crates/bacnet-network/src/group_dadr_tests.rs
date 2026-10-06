//! A routed NPDU whose DADR is a group destination on the port the router
//! delivers it on (#1504), on the wire.
//!
//! Delivered as one unicast, such an NPDU reaches every node in the group
//! without the broadcast network addresses #1491 filters, so the router
//! delivers only an Unconfirmed-Request there. The fixture's port B counts
//! MAC 0xFF as its broadcast. Hand-built NPDUs go in at peer A; an
//! Unconfirmed-Request sent right after the refused ones is the first frame
//! out of port B, which shows the refused ones went nowhere.

use bacnet_encoding::npdu::{encode_npdu, Npdu, NpduAddress, RejectMessageToNetwork};
use bacnet_types::enums::RejectMessageReason;
use bacnet_types::MacAddr;
use bytes::{Bytes, BytesMut};

use crate::loopback_fixture::{next_from_router, reject_of, RouterFixture, APDU, REMOTE};

/// A group destination on port B (network 2000).
const GROUP: u8 = 0xFF;
/// A ReadProperty Confirmed-Request for Device 1's Object_Name.
const CONFIRMED_REQUEST: &[u8] = &[
    0x00, 0x05, 0x01, 0x0C, 0x0C, 0x02, 0x00, 0x00, 0x01, 0x19, 0x4D,
];
/// Its ComplexACK, with the name "A".
const COMPLEX_ACK: &[u8] = &[
    0x30, 0x01, 0x0C, 0x0C, 0x02, 0x00, 0x00, 0x01, 0x19, 0x4D, 0x3E, 0x75, 0x02, 0x00, 0x41, 0x3F,
];

/// An NPDU for `dadr` on network `dnet`, carrying `apdu`.
fn routed(dnet: u16, dadr: u8, apdu: &[u8]) -> Bytes {
    let npdu = Npdu {
        destination: Some(NpduAddress {
            network: dnet,
            mac_address: MacAddr::from_slice(&[dadr]),
        }),
        hop_count: 255,
        payload: Bytes::copy_from_slice(apdu),
        ..Npdu::default()
    };
    let mut bytes = BytesMut::new();
    encode_npdu(&mut bytes, &npdu).unwrap();
    bytes.freeze()
}

#[tokio::test]
async fn router_delivers_only_an_unconfirmed_request_to_a_group_dadr() {
    let mut fixture = RouterFixture::start_with_group_on_b(GROUP).await;
    // Refused: a request and an answer for the group on network 2000.
    fixture
        .send_from_a(&routed(2000, GROUP, CONFIRMED_REQUEST))
        .await;
    fixture.send_from_a(&routed(2000, GROUP, COMPLEX_ACK)).await;
    // Passed on: the same MAC on network 3000 behind peer B, which is the
    // next router's to judge; an Unconfirmed-Request for the group; and a
    // request for one device on network 2000.
    fixture
        .send_from_a(&routed(REMOTE, GROUP, CONFIRMED_REQUEST))
        .await;
    fixture.send_from_a(&routed(2000, GROUP, &APDU)).await;
    fixture
        .send_from_a(&routed(2000, 0x0B, CONFIRMED_REQUEST))
        .await;
    // No route: a reject comes back to A.
    fixture.send_from_a(&routed(5000, 0x0B, &APDU)).await;

    let (remote, to) = next_from_router(&mut fixture.from_router_b).await;
    assert_eq!(to.as_deref(), Some(&[0x0B][..]), "the next hop");
    assert_eq!(remote.payload, CONFIRMED_REQUEST);
    let dadr = remote.destination.map(|to| (to.network, to.mac_address));
    assert_eq!(dadr, Some((REMOTE, MacAddr::from_slice(&[GROUP]))));
    let (group, to) = next_from_router(&mut fixture.from_router_b).await;
    assert_eq!(to.as_deref(), Some(&[GROUP][..]));
    assert_eq!(group.payload, APDU[..]);
    assert_eq!(group.destination, None, "network 2000 is port B's own");
    let (one, to) = next_from_router(&mut fixture.from_router_b).await;
    assert_eq!(to.as_deref(), Some(&[0x0B][..]));
    assert_eq!(one.payload, CONFIRMED_REQUEST);
    // The refused ones drew no reject: the one for network 5000 is first.
    let (reject, _) = next_from_router(&mut fixture.from_router_a).await;
    assert_eq!(
        reject_of(&reject),
        RejectMessageToNetwork {
            reason: RejectMessageReason::NOT_DIRECTLY_CONNECTED,
            dnet: 5000,
        }
    );

    assert_eq!(fixture.router.group_dadr_drops(), 2);
    assert_eq!(fixture.router.broadcast_pdu_type_drops(), 0);
    fixture.stop().await;
}

/// The same holds for delivery back out the port the NPDU arrived on: a
/// node on network 2000 addressing the group there through the router.
#[tokio::test]
async fn router_delivers_back_out_the_arrival_port_only_an_unconfirmed_request() {
    let mut fixture = RouterFixture::start_with_group_on_b(GROUP).await;
    fixture
        .send_from_b(&routed(2000, GROUP, CONFIRMED_REQUEST))
        .await;
    fixture.send_from_b(&routed(2000, GROUP, &APDU)).await;

    let (back, to) = next_from_router(&mut fixture.from_router_b).await;
    assert_eq!(to.as_deref(), Some(&[GROUP][..]));
    assert_eq!(back.payload, APDU[..], "the refused request went nowhere");
    assert_eq!(fixture.router.group_dadr_drops(), 1);
    fixture.stop().await;
}
