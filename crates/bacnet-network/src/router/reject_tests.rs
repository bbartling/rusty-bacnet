//! Reject addressing and relay at the send-queue level (#1158), where the
//! link MAC each reject goes to is visible. The loopback tests in
//! `crate::reject_route_tests` cover the same paths on the wire.

use super::super::envelope_harness::{attributes, Harness};
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

#[test]
fn send_reject_addresses_the_originator_or_the_local_sender() {
    let origin = NpduAddress {
        network: 4000,
        mac_address: MacAddr::from_slice(&[0x50, 0x51]),
    };
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
        let (tx, mut rx) = mpsc::channel(4);
        let sender_mac = [0x0A, 0x00, 0x01, 0x01];
        let data_attributes = attributes();
        let refused = Refused {
            send_tx: &tx,
            sender_mac: &sender_mac,
            origin,
            data_attributes: &data_attributes,
        };
        send_reject(&refused, 5000, RejectMessageReason::NOT_DIRECTLY_CONNECTED);

        let (npdu, mac, sent_attributes) = unicast(rx.try_recv().unwrap());
        assert_eq!(npdu, expected, "{origin:?}");
        assert_eq!(mac.as_slice(), sender_mac, "goes to the link sender");
        assert_eq!(sent_attributes, data_attributes);
        assert!(rx.try_recv().is_err());
    }
}

/// Direct 1000/0 and 2000/1, and 3000 learned behind [9] on port 0.
fn relay_harness() -> Harness {
    let mut table = RouterTable::new();
    table.add_direct(1000, 0);
    table.add_direct(2000, 1);
    table.add_learned(3000, 0, MacAddr::from_slice(&[9]));
    Harness::with_table(table)
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
