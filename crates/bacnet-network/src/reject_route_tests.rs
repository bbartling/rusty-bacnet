//! Where the router's Reject-Message-To-Network goes (#1158), on the wire.
//!
//! Per Clause 6.4.4, a reject is meant for whoever first sent the refused NPDU.
//! A relayed NPDU names that node in its SNET/SADR, so the reject carries it
//! as DNET/DADR and goes back to the router that relayed the NPDU; an NPDU
//! from the arrival link draws a plain local unicast, and so does one whose
//! SNET is the arrival network (#1174). A received reject is relayed by its
//! DNET/DADR (Clause 6.6.3.5), which is what carries a reject back across a
//! chain of routers to the device, unless it is addressed to the router
//! itself, when it reaches the router's control receiver instead (#1175).
//! Every reject is compared byte for byte.

use bacnet_encoding::npdu::decode_npdu;
use bacnet_transport::loopback::LoopbackTransport;
use bacnet_transport::port::TransportPort;
use bacnet_types::enums::NetworkMessageType;
use bacnet_types::MacAddr;
use bytes::Bytes;

use crate::loopback_fixture::{
    next_frame_from_router, recv, wire, RouterFixture, ORIGIN, REMOTE, TOO_LONG,
};
use crate::router::{BACnetRouter, RouterPort};
use crate::router_table::ReachabilityStatus;

/// A network the fixture router has no route to.
const UNKNOWN: u16 = 5000;
const WHO_IS: u8 = NetworkMessageType::WHO_IS_ROUTER_TO_NETWORK.to_raw();
/// A reserved network message type, which the router answers with reason 3.
const RESERVED_TYPE: u8 = 0x14;

/// One way the router refuses an NPDU from peer A: the frame, built with the
/// SNET/SADR it is given, and the reject payload it draws (reason, network).
struct Refusal {
    what: &'static str,
    /// Peer B declares network 3000 busy first.
    busy: bool,
    frame: fn(Option<(u16, u8)>) -> Vec<u8>,
    reject: [u8; 3],
}

/// Every reject this router originates, one per call site.
fn refusals() -> [Refusal; 6] {
    [
        Refusal {
            what: "reason 1, APDU to an unknown DNET",
            busy: false,
            frame: |source| wire(Some((UNKNOWN, 0)), source, None),
            reject: [0x01, 0x13, 0x88],
        },
        Refusal {
            what: "reason 1, directed control to an unknown DNET",
            busy: false,
            frame: |source| wire(Some((UNKNOWN, 0)), source, Some(WHO_IS)),
            reject: [0x01, 0x13, 0x88],
        },
        Refusal {
            what: "reason 2, APDU to a busy DNET",
            busy: true,
            frame: |source| wire(Some((REMOTE, 1)), source, None),
            reject: [0x02, 0x0B, 0xB8],
        },
        Refusal {
            what: "reason 2, directed control to a busy DNET",
            busy: true,
            frame: |source| wire(Some((REMOTE, 1)), source, Some(WHO_IS)),
            reject: [0x02, 0x0B, 0xB8],
        },
        Refusal {
            what: "reason 3, reserved message type",
            busy: false,
            frame: |source| wire(None, source, Some(RESERVED_TYPE)),
            reject: [0x03, 0x00, 0x00],
        },
        Refusal {
            what: "reason 6, over-long DADR",
            busy: false,
            frame: |source| wire(Some((REMOTE, TOO_LONG)), source, None),
            reject: [0x06, 0x0B, 0xB8],
        },
    ]
}

/// Send `frame` from peer A to a fresh fixture router and return the first
/// frame the router sends back to peer A.
async fn first_answer(busy: bool, frame: &[u8]) -> Vec<u8> {
    let mut fixture = RouterFixture::start().await;
    if busy {
        let busy = Some(NetworkMessageType::ROUTER_BUSY_TO_NETWORK.to_raw());
        fixture
            .peer_b
            .send_broadcast(&wire(None, None, busy))
            .await
            .unwrap();
        // The router marks 3000 busy before passing the message on to port A.
        let (relayed, _) = next_frame_from_router(&mut fixture.from_router_a).await;
        assert_eq!(relayed[..], [0x01, 0x80, 0x04, 0x0B, 0xB8]);
    }
    fixture.send_from_a(frame).await;
    let (answer, broadcast) = next_frame_from_router(&mut fixture.from_router_a).await;
    assert!(!broadcast, "a reject is a unicast");
    fixture.stop().await;
    answer.to_vec()
}

#[tokio::test]
async fn router_rejects_a_relayed_npdu_toward_its_snet_sadr() {
    for refusal in refusals() {
        // SNET 4000, SADR 50: the reject's DNET 4000, DLEN 1, DADR 50 and a
        // full hop count, sent back to peer A, the router that relayed it.
        let mut expected = vec![0x01, 0xA0, 0x0F, 0xA0, 0x01, 0x50, 0xFF, 0x03];
        expected.extend_from_slice(&refusal.reject);
        let answer = first_answer(refusal.busy, &(refusal.frame)(Some((ORIGIN, 1)))).await;
        assert_eq!(answer, expected, "{}", refusal.what);
    }
}

#[tokio::test]
async fn router_rejects_a_local_npdu_with_a_local_unicast() {
    for refusal in refusals() {
        let mut expected = vec![0x01, 0x80, 0x03];
        expected.extend_from_slice(&refusal.reject);
        let answer = first_answer(refusal.busy, &(refusal.frame)(None)).await;
        assert_eq!(answer, expected, "{}", refusal.what);
    }
}

#[tokio::test]
async fn router_rejects_an_npdu_from_its_own_snet_with_a_local_unicast() {
    // SNET 1000 is the network peer A's port is on (#1174), so the
    // originator, SADR 50, is on that link: no DNET, and the frame is the
    // same local unicast an NPDU without SNET/SADR draws.
    for refusal in refusals() {
        let mut expected = vec![0x01, 0x80, 0x03];
        expected.extend_from_slice(&refusal.reject);
        let answer = first_answer(refusal.busy, &(refusal.frame)(Some((1000, 1)))).await;
        assert_eq!(answer, expected, "{}", refusal.what);
    }
}

#[tokio::test]
async fn router_falls_back_to_a_local_unicast_when_the_sadr_is_too_long() {
    // The over-long SADR names no node, so the link sender gets the reason 6
    // reject, still naming the refused DNET.
    for frame in [
        wire(Some((REMOTE, 1)), Some((ORIGIN, TOO_LONG)), None),
        wire(Some((REMOTE, TOO_LONG)), Some((ORIGIN, TOO_LONG)), None),
    ] {
        let answer = first_answer(false, &frame).await;
        assert_eq!(answer, [0x01, 0x80, 0x03, 0x06, 0x0B, 0xB8], "{frame:02X?}");
    }
}

#[tokio::test]
async fn router_relays_a_received_reject_to_the_node_its_dnet_names() {
    let mut fixture = RouterFixture::start().await;
    // A reject with no DNET is addressed to this router and goes no further,
    // even with SNET/SADR on it.
    fixture
        .send_from_b(&[0x01, 0x88, 0x03, 0xE8, 0x01, 0x0C, 0x03, 0x01, 0x13, 0x88])
        .await;
    // DNET 1000, DADR 0C: directly connected on port A.
    fixture
        .send_from_b(&[
            0x01, 0xA0, 0x03, 0xE8, 0x01, 0x0C, 0xFF, 0x03, 0x01, 0x13, 0x88,
        ])
        .await;
    let (relayed, broadcast) = next_frame_from_router(&mut fixture.from_router_a).await;
    assert!(!broadcast);
    // DNET/DADR come off; SNET 2000 / SADR 0B (peer B) go on.
    assert_eq!(
        relayed[..],
        [0x01, 0x88, 0x07, 0xD0, 0x01, 0x0B, 0x03, 0x01, 0x13, 0x88]
    );
    fixture.stop().await;
}

#[tokio::test]
async fn router_hands_a_reject_addressed_to_itself_to_its_control_receiver() {
    // The router is 01 on 1000 and 02 on 2000. Peer B sends each reject,
    // reason 2 for 3000, the network that lies behind peer B.
    let cases: [(&str, &[u8]); 3] = [
        ("no DNET", &[0x01, 0x80, 0x03, 0x02, 0x0B, 0xB8]),
        (
            "DNET 2000, DADR 02: the arrival port",
            &[
                0x01, 0xA0, 0x07, 0xD0, 0x01, 0x02, 0xFF, 0x03, 0x02, 0x0B, 0xB8,
            ],
        ),
        (
            "DNET 1000, DADR 01: the other port",
            &[
                0x01, 0xA0, 0x03, 0xE8, 0x01, 0x01, 0xFF, 0x03, 0x02, 0x0B, 0xB8,
            ],
        ),
    ];
    for (case, reject) in cases {
        let (mut fixture, mut controls) = RouterFixture::start_with_network_control().await;
        fixture.send_from_b(reject).await;

        let control = recv(&mut controls).await;
        let sent = decode_npdu(Bytes::copy_from_slice(reject)).unwrap();
        assert_eq!(control.npdu, sent, "{case}");
        assert_eq!(control.source_mac.as_slice(), [0x0B], "{case}");
        assert_eq!(control.ingress_sequence, 1, "{case}");
        assert_eq!(fixture.router.network_control_ingress_sequence(), 1);
        assert_eq!(
            fixture
                .router
                .table()
                .lock()
                .await
                .effective_reachability(REMOTE),
            Some(ReachabilityStatus::Busy),
            "{case}: the table still learns from it"
        );
        // A reject for device 0C on 1000 is the next frame on port A, so
        // nothing was relayed there before it.
        fixture
            .send_from_b(&[
                0x01, 0xA0, 0x03, 0xE8, 0x01, 0x0C, 0xFF, 0x03, 0x01, 0x13, 0x88,
            ])
            .await;
        let (relayed, _) = next_frame_from_router(&mut fixture.from_router_a).await;
        assert_eq!(
            relayed[..],
            [0x01, 0x88, 0x07, 0xD0, 0x01, 0x0B, 0x03, 0x01, 0x13, 0x88],
            "{case}"
        );
        assert!(controls.try_recv().is_err(), "{case}");
        fixture.stop().await;
    }
}

#[tokio::test]
async fn chained_routers_carry_a_reject_back_to_the_originating_device() {
    // device 0A --[1000]-- 01 R1 02 --[2000]-- 03 R2 04 --[3000]-- 0C
    let (r1_a, mut device) = LoopbackTransport::pair(vec![0x01], vec![0x0A]);
    let (r1_b, r2_a) = LoopbackTransport::pair(vec![0x02], vec![0x03]);
    let (r2_b, mut far) = LoopbackTransport::pair(vec![0x04], vec![0x0C]);
    let mut to_device = device.start().await.unwrap();
    let _to_far = far.start().await.unwrap();
    let (mut r1, _r1_local) = BACnetRouter::start(vec![
        RouterPort {
            transport: r1_a,
            network_number: 1000,
        },
        RouterPort {
            transport: r1_b,
            network_number: 2000,
        },
    ])
    .await
    .unwrap();
    let (mut r2, _r2_local) = BACnetRouter::start(vec![
        RouterPort {
            transport: r2_a,
            network_number: 2000,
        },
        RouterPort {
            transport: r2_b,
            network_number: 3000,
        },
    ])
    .await
    .unwrap();
    // R1 sends traffic for 5000 to R2, which has no route there.
    r1.table()
        .lock()
        .await
        .add_learned(UNKNOWN, 1, MacAddr::from_slice(&[0x03]));

    device
        .send_unicast(&wire(Some((UNKNOWN, 0)), None, None), &[0x01])
        .await
        .unwrap();

    // R2 rejects toward 1000/0A, the SNET/SADR R1 put on the NPDU, through
    // R1; R1 relays it by that DNET to the device, from 2000/03.
    let (reject, broadcast) = next_frame_from_router(&mut to_device).await;
    assert!(!broadcast);
    assert_eq!(
        reject[..],
        [0x01, 0x88, 0x07, 0xD0, 0x01, 0x03, 0x03, 0x01, 0x13, 0x88]
    );

    r1.stop().await;
    r2.stop().await;
    device.stop().await.unwrap();
    far.stop().await.unwrap();
}
