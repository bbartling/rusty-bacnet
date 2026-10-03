//! Reject addressing and relay at the send-queue level (#1158), where the
//! port and link MAC each reject goes to are visible, and the rejects that
//! stop at the router's own network-control consumer (#1175). The loopback
//! tests in `crate::reject_route_tests` cover the same paths on the wire.

use std::sync::Arc;

use super::super::control_policy::ControlGate;
use super::super::envelope_harness::{attributes, own_addresses, Harness, PORT_MACS};
use super::*;
use bytes::Bytes;

/// Reason 1 for network 5000: the payload every reject below carries.
const NO_ROUTE_TO_5000: [u8; 3] = [0x01, 0x13, 0x88];

fn unicast(request: SendRequest) -> (Vec<u8>, MacAddr, Vec<DataAttribute>) {
    match request {
        SendRequest::Unicast {
            npdu,
            mac,
            data_attributes,
        } => (npdu.to_vec(), mac, data_attributes),
        SendRequest::Broadcast { .. } => panic!("expected a unicast"),
    }
}

/// The link sender of every NPDU refused below.
const SENDER: [u8; 4] = [0x0A, 0x00, 0x01, 0x01];

fn address(network: u16, mac: &[u8]) -> NpduAddress {
    NpduAddress {
        network,
        mac_address: MacAddr::from_slice(mac),
    }
}

/// Refuse an NPDU from [`SENDER`] on port 0 (network 1000) whose SNET/SADR is
/// `origin` with reason 1 for 5000, and return what each port's send queue
/// then holds. The harness router is [01] on 1000 and [02] on 2000.
fn reject_for(origin: Option<&NpduAddress>) -> [Vec<SendRequest>; 2] {
    let (txs, mut rxs): (Vec<_>, Vec<_>) = (0..2).map(|_| mpsc::channel(4)).unzip();
    let own = own_addresses();
    let data_attributes = attributes();
    let refused = Refused {
        send_txs: &txs,
        own: &own,
        port_idx: 0,
        sender_mac: &SENDER,
        origin,
        data_attributes: &data_attributes,
    };
    send_reject(&refused, 5000, RejectMessageReason::NOT_DIRECTLY_CONNECTED);
    [0, 1].map(|port| std::iter::from_fn(|| rxs[port].try_recv().ok()).collect())
}

/// The one unicast in `sent`, which must carry the ingress attributes.
fn only_unicast(mut sent: Vec<SendRequest>) -> (Vec<u8>, MacAddr) {
    assert_eq!(sent.len(), 1, "exactly one reject");
    let (npdu, mac, data_attributes) = unicast(sent.pop().unwrap());
    assert_eq!(data_attributes, attributes());
    (npdu, mac)
}

#[test]
fn send_reject_addresses_the_originator_or_the_local_sender() {
    let origin = address(4000, &[0x50, 0x51]);
    let cases: [(Option<&NpduAddress>, &[u8]); 2] = [
        // A relayed NPDU: DNET 4000, DLEN 2, DADR 50 51, hop count 255.
        (
            Some(&origin),
            &[
                0x01, 0xA0, 0x0F, 0xA0, 0x02, 0x50, 0x51, 0xFF, 0x03, 0x01, 0x13, 0x88,
            ],
        ),
        // A local sender: no addressing at all.
        (None, &[0x01, 0x80, 0x03, 0x01, 0x13, 0x88]),
    ];
    for (origin, expected) in cases {
        let [arrival, other] = reject_for(origin);
        let (npdu, mac) = only_unicast(arrival);
        assert_eq!(npdu, expected, "{origin:?}");
        assert_eq!(mac.as_slice(), SENDER, "goes to the link sender");
        assert!(other.is_empty(), "{origin:?}");
    }
}

#[test]
fn send_reject_unicasts_an_originator_on_the_arrival_network_to_its_sadr() {
    // SNET 1000 is the arrival port's own network (#1174): the originator is
    // on this link, so the reject carries no DNET and goes to the SADR, not
    // to the link sender.
    let origin = address(1000, &[0x50, 0x51]);
    let [arrival, other] = reject_for(Some(&origin));
    let (npdu, mac) = only_unicast(arrival);
    assert_eq!(npdu, [0x01, 0x80, 0x03, 0x01, 0x13, 0x88]);
    assert_eq!(mac, origin.mac_address);
    assert!(other.is_empty());
}

#[test]
fn send_reject_sends_an_originator_on_another_direct_network_out_its_port() {
    // SNET 2000 is the network on port 1, so the NPDU looped round to port 0
    // (#1219). The reject leaves by port 1 as a local unicast to the SADR.
    let origin = address(2000, &[0x50, 0x51]);
    let [arrival, other] = reject_for(Some(&origin));
    assert!(arrival.is_empty(), "nothing goes back to the link sender");
    let (npdu, mac) = only_unicast(other);
    assert_eq!(npdu, [0x01, 0x80, 0x03, 0x01, 0x13, 0x88]);
    assert_eq!(mac, origin.mac_address);
}

#[test]
fn send_reject_sends_nothing_when_the_originator_is_the_router() {
    // The router's own MAC on the arrival network, and on the other one: no
    // reject goes out on either port (#1219).
    for origin in [
        address(1000, &[PORT_MACS[0]]),
        address(2000, &[PORT_MACS[1]]),
    ] {
        let [arrival, other] = reject_for(Some(&origin));
        assert!(arrival.is_empty(), "{origin:?}");
        assert!(other.is_empty(), "{origin:?}");
    }

    // Port 1's MAC paired with network 1000 is some other node on that link.
    let origin = address(1000, &[PORT_MACS[1]]);
    let [arrival, other] = reject_for(Some(&origin));
    assert_eq!(only_unicast(arrival).1, origin.mac_address);
    assert!(other.is_empty());
}

/// Direct 1000/0 and 2000/1, and 3000 learned behind [9] on port 0.
fn relay_table() -> RouterTable {
    let mut table = RouterTable::new();
    table.add_direct(1000, 0);
    table.add_direct(2000, 1);
    table.add_learned(3000, 0, MacAddr::from_slice(&[9]));
    table
}

fn relay_harness() -> Harness {
    Harness::with_table(relay_table())
}

fn received_reject(
    destination: Option<(u16, &[u8])>,
    source: Option<(u16, &[u8])>,
    hop: u8,
) -> Npdu {
    let address = |(network, mac): (u16, &[u8])| NpduAddress {
        network,
        mac_address: MacAddr::from_slice(mac),
    };
    Npdu {
        is_network_message: true,
        message_type: Some(NetworkMessageType::REJECT_MESSAGE_TO_NETWORK.to_raw()),
        destination: destination.map(address),
        source: source.map(address),
        hop_count: hop,
        payload: Bytes::copy_from_slice(&NO_ROUTE_TO_5000),
        ..Npdu::default()
    }
}

/// A received reject's DNET/DADR, and the frame and link MAC it is relayed
/// with.
struct Relayed {
    dnet: u16,
    dadr: &'static [u8],
    link_mac: &'static [u8],
    npdu: &'static [u8],
}

#[tokio::test]
async fn relay_routes_a_received_reject_by_its_dnet() {
    let cases = [
        // Directly connected: DNET/DADR come off, SNET 2000 / SADR [2] go on,
        // and the reject goes straight to the DADR.
        Relayed {
            dnet: 1000,
            dadr: &[0x0A],
            link_mac: &[0x0A],
            npdu: &[0x01, 0x88, 0x07, 0xD0, 0x01, 0x02, 0x03, 0x01, 0x13, 0x88],
        },
        // Behind another router: DNET/DADR stay, one hop is spent, and the
        // reject goes to the next hop.
        Relayed {
            dnet: 3000,
            dadr: &[0x30],
            link_mac: &[9],
            npdu: &[
                0x01, 0xA8, 0x0B, 0xB8, 0x01, 0x30, 0x07, 0xD0, 0x01, 0x02, 0xFE, 0x03, 0x01, 0x13,
                0x88,
            ],
        },
    ];
    for case in cases {
        let dnet = case.dnet;
        let mut h = relay_harness();
        let mut ctx = h.ctx(1, &[2], received_reject(Some((dnet, case.dadr)), None, 255));
        ctx.data_attributes = attributes();
        h.handle(ctx).await;

        let mut relayed = h.drain(0);
        assert_eq!(relayed.len(), 1, "DNET {dnet}");
        let (npdu, mac, data_attributes) = unicast(relayed.pop().unwrap());
        assert_eq!(npdu, case.npdu, "DNET {dnet}");
        assert_eq!(mac.as_slice(), case.link_mac, "DNET {dnet}");
        assert_eq!(data_attributes, attributes());
        assert!(h.drain(1).is_empty(), "DNET {dnet}: nothing goes back");
    }
}

#[tokio::test]
async fn relay_drops_a_received_reject_it_cannot_route() {
    let cases = [
        // No DNET: addressed to this router, even with SNET/SADR present.
        ("no DNET", received_reject(None, Some((1000, &[0x0A])), 255)),
        (
            "global DNET",
            received_reject(Some((0xFFFF, &[])), None, 255),
        ),
        (
            "arrival network",
            received_reject(Some((2000, &[0x20])), None, 255),
        ),
        (
            "unknown DNET",
            received_reject(Some((6000, &[0x60])), None, 255),
        ),
        (
            "no hops left",
            received_reject(Some((3000, &[0x30])), None, 0),
        ),
    ];
    for (case, npdu) in cases {
        let mut h = relay_harness();
        h.handle(h.ctx(1, &[2], npdu)).await;
        assert!(h.drain(0).is_empty(), "{case}");
        assert!(
            h.drain(1).is_empty(),
            "{case}: never answered with a reject"
        );
    }
}

/// A reject from [0B] on port 1 (network 2000), reason 2 for network 3000,
/// with the given DNET and one-octet DADR.
fn busy_3000_reject(h: &Harness, destination: Option<(u16, u8)>) -> (Npdu, IngressContext) {
    let mut npdu = received_reject(None, None, 255);
    npdu.destination = destination.map(|(network, mac)| NpduAddress {
        network,
        mac_address: MacAddr::from_slice(&[mac]),
    });
    npdu.payload = Bytes::from_static(&[0x02, 0x0B, 0xB8]);
    let mut ctx = h.ctx(1, &[0x0B], npdu.clone());
    ctx.data_attributes = attributes();
    (npdu, ctx)
}

#[tokio::test]
async fn a_reject_addressed_to_the_router_reaches_its_consumer_and_the_table() {
    // The router's own MACs are [01] on 1000 and [02] on 2000.
    let cases = [
        ("no DNET", None),
        ("own MAC on the arrival network", Some((2000, PORT_MACS[1]))),
        (
            "own MAC on the other port's network",
            Some((1000, PORT_MACS[0])),
        ),
    ];
    for (case, destination) in cases {
        let mut h = relay_harness();
        let mut controls = h.network_control();
        let (npdu, ctx) = busy_3000_reject(&h, destination);
        h.handle(ctx).await;

        let control = controls.try_recv().expect(case);
        assert_eq!(control.npdu, npdu, "{case}");
        assert_eq!(control.source_mac.as_slice(), [0x0B], "{case}");
        assert_eq!(control.data_attributes, attributes(), "{case}");
        assert_eq!(control.ingress_sequence, 1, "{case}");
        assert!(controls.try_recv().is_err(), "{case}");
        assert_eq!(
            h.table.lock().await.effective_reachability(3000),
            Some(ReachabilityStatus::Busy),
            "{case}: the table still learns from it"
        );
        assert!(h.drain(0).is_empty(), "{case}: not relayed");
        assert!(h.drain(1).is_empty(), "{case}: not relayed");
    }
}

#[tokio::test]
async fn a_reject_for_another_node_or_a_denied_one_skips_the_routers_consumer() {
    // Meant for other nodes, so relayed out port 0: a device on 1000, and
    // the router's port 1 MAC paired with the wrong network.
    for dadr in [0x0A, PORT_MACS[1]] {
        let mut h = relay_harness();
        let mut controls = h.network_control();
        let (_, ctx) = busy_3000_reject(&h, Some((1000, dadr)));
        h.handle(ctx).await;
        assert_eq!(h.drain(0).len(), 1, "DADR {dadr:02X}");
        assert!(controls.try_recv().is_err(), "DADR {dadr:02X}");
    }

    // A reject the control policy denies changes nothing and reaches no one.
    let mut h = Harness::with_gate(relay_table(), Arc::new(ControlGate::hardened()));
    let mut controls = h.network_control();
    let (_, ctx) = busy_3000_reject(&h, None);
    h.handle(ctx).await;
    assert!(controls.try_recv().is_err());
    assert_eq!(
        h.table.lock().await.effective_reachability(3000),
        Some(ReachabilityStatus::Reachable)
    );
    h.assert_quiet();
}
