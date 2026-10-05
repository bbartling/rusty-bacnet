//! Reject-Message-To-Network: the rejects this router sends and the ones it
//! passes on (#1158).
//!
//! Per Clause 6.4.4, a reject is meant for whoever first sent the refused
//! message, and that message's source fields say who that is. Every reject
//! this router originates (reasons 1, 2, 3 and 6) goes through
//! [`send_reject`], which addresses it from the refused NPDU's SNET/SADR. A
//! received reject goes to [`route_received_reject`]: one addressed to this
//! router stops here and reaches the router's own network-control consumer
//! (#1175), and any other is routed by the DNET/DADR such a reject carries.

use std::sync::atomic::AtomicU64;

use bacnet_encoding::npdu::{encode_npdu, Npdu, NpduAddress, NpduDecodeError};
use bacnet_transport::port::{DataAttribute, ReceivedNpdu};
use bacnet_types::enums::{NetworkMessageType, RejectMessageReason};
use bacnet_types::MacAddr;
use bytes::{BufMut, BytesMut};
use tokio::sync::{mpsc, Mutex};
use tracing::{debug, warn};

use super::forwarding::forward_unicast;
use super::local_control::{LocalControl, OwnAddresses};
use super::{IngressContext, SendRequest};
use crate::layer::count_drop;
use crate::router_table::{ReachabilityStatus, RouterTable};

/// What a reject needs to know about the NPDU it refuses.
pub(super) struct Refused<'a> {
    /// Every port's send queue, by port index.
    pub send_txs: &'a [mpsc::Sender<SendRequest>],
    /// The router's own address on each port.
    pub own: &'a OwnAddresses,
    /// Index of the port the refused NPDU arrived on.
    pub port_idx: usize,
    /// Link-layer source of the refused NPDU: the node that handed it to us.
    pub sender_mac: &'a [u8],
    /// The refused NPDU's SNET/SADR, present when a router relayed it.
    pub origin: Option<&'a NpduAddress>,
    /// Ingress data attributes, which travel with the reject (RB-03).
    pub data_attributes: &'a [DataAttribute],
}

impl<'a> Refused<'a> {
    /// A decoded NPDU refused on port `port_idx`.
    pub(super) fn frame(
        send_txs: &'a [mpsc::Sender<SendRequest>],
        own: &'a OwnAddresses,
        port_idx: usize,
        received: &'a ReceivedNpdu,
        npdu: &'a Npdu,
    ) -> Self {
        Self {
            send_txs,
            own,
            port_idx,
            sender_mac: &received.source_mac,
            origin: npdu.source.as_ref(),
            data_attributes: &received.data_attributes,
        }
    }

    /// A network message refused at the control admission point.
    pub(super) fn control(
        send_txs: &'a [mpsc::Sender<SendRequest>],
        own: &'a OwnAddresses,
        ctx: &'a IngressContext,
    ) -> Self {
        Self {
            send_txs,
            own,
            port_idx: ctx.port_idx,
            sender_mac: &ctx.source_mac,
            origin: ctx.npdu.source.as_ref(),
            data_attributes: &ctx.data_attributes,
        }
    }

    /// The port the reject leaves by, the DNET/DADR it carries and the MAC
    /// it is unicast to, or `None` when the refused NPDU names this router
    /// as its originator. See [`send_reject`].
    fn reject_path(&self) -> Option<(usize, Option<NpduAddress>, &'a [u8])> {
        let Some(origin) = self.origin else {
            return Some((self.port_idx, None, self.sender_mac));
        };
        if self.own.contains(origin) {
            return None;
        }
        Some(match self.own.port_on(origin.network) {
            Some(port) => (port, None, &origin.mac_address[..]),
            None => (self.port_idx, Some(origin.clone()), self.sender_mac),
        })
    }
}

/// The reject reason for a route the table holds but cannot use right now
/// (Clauses 6.6.3.5 and 6.6.3.6), or `None` when the route is usable.
pub(super) fn route_refusal(
    reachability: Option<ReachabilityStatus>,
) -> Option<RejectMessageReason> {
    match reachability.unwrap_or(ReachabilityStatus::Reachable) {
        ReachabilityStatus::Busy => Some(RejectMessageReason::ROUTER_BUSY),
        ReachabilityStatus::Unreachable => Some(RejectMessageReason::NOT_DIRECTLY_CONNECTED),
        ReachabilityStatus::Reachable => None,
    }
}

/// Queue the Reject-Message-To-Network that answers `refused`, naming
/// `rejected_network`.
///
/// The reject is for whoever first sent the refused NPDU (Clause 6.4.4), and
/// it travels the way this router would route anything to that node:
///
/// - Without SNET/SADR, the NPDU came from the arrival link itself, and the
///   reject is a plain local unicast back to its sender.
/// - An SNET that is one of the router's own networks puts the originator on
///   a directly connected link: the arrival one (#1174) or, when the NPDU
///   looped back through another path, a different one (#1219). Clause 6.5.4
///   has a router reach such a node by leaving out DNET/DADR and sending
///   straight to its MAC, so the reject leaves by the port attached to SNET
///   as a local unicast to the SADR. Given a DNET and sent to the link
///   sender instead, it would be lost or sent round again: a non-router
///   discards an NPDU that names a remote DNET (Clause 6.5.2.1).
/// - If that SNET/SADR is the router's own address on the network, the NPDU
///   came back to the router that sent it, and no reject goes out (#1219).
/// - Any other SNET is remote, so the originator sits behind the router that
///   relayed the NPDU. The reject names the originator as its DNET/DADR,
///   starts with a full hop count, and goes back out the arrival port to the
///   link sender, which knows the way back.
///
/// Locally generated, but ingress-triggered: the caller's data attributes
/// travel with the reject instead of being silently dropped (RB-03).
pub(super) fn send_reject(
    refused: &Refused<'_>,
    rejected_network: u16,
    reason: RejectMessageReason,
) {
    let Some((port, destination, link_mac)) = refused.reject_path() else {
        debug!(
            network = rejected_network,
            "Router refused an NPDU it originated itself; no reject sent"
        );
        return;
    };

    let mut payload = BytesMut::with_capacity(3);
    payload.put_u8(reason.to_raw());
    payload.put_u16(rejected_network);

    let reject = Npdu {
        is_network_message: true,
        message_type: Some(NetworkMessageType::REJECT_MESSAGE_TO_NETWORK.to_raw()),
        destination,
        hop_count: 255,
        payload: payload.freeze(),
        ..Npdu::default()
    };

    let mut buf = BytesMut::with_capacity(32);
    if let Err(e) = encode_npdu(&mut buf, &reject) {
        warn!("Failed to encode Reject-Message NPDU: {e}");
        return;
    }

    if let Err(e) = refused.send_txs[port].try_send(SendRequest::unicast_with_attributes(
        buf.freeze(),
        MacAddr::from_slice(link_mac),
        refused.data_attributes,
    )) {
        warn!(%e, "Router dropped reject message: output channel full");
    }
}

/// Refuse an NPDU whose DLEN or SLEN is past `NpduAddress::MAX_MAC_LEN`
/// (#1141): count it, never forward or deliver it, and reject it when it names
/// a specific DNET.
///
/// Reject reason 6 covers a DADR or SADR of invalid length (Clause 6.4.4), and
/// Clause 6.6.3.5 has a router reject what it cannot relay toward a DNET. When
/// the DADR is the bad field, the decoder still reports the SNET/SADR behind
/// it, and the reject goes there like any other (#1158). When the SADR is the
/// bad field, the originator cannot be addressed, so the reject falls back to
/// a local unicast to the link sender: it is the only node that can be told,
/// and a router there at least learns its relay failed. A global broadcast,
/// like everywhere else in this router, draws no reject, and an NPDU without a
/// DNET has none to report, so both are only dropped.
pub(super) fn refuse_address_too_long(
    send_txs: &[mpsc::Sender<SendRequest>],
    own: &OwnAddresses,
    port_idx: usize,
    received: &ReceivedNpdu,
    refused: &NpduDecodeError,
    drops: &AtomicU64,
) {
    warn!(error = %refused, port = port_idx, "Router refused an NPDU");
    count_drop(drops);
    let NpduDecodeError::AddressTooLong { dnet, source, .. } = refused else {
        return;
    };
    if let Some(dnet) = dnet.filter(|&dnet| dnet != 0xFFFF) {
        let refused = Refused {
            send_txs,
            own,
            port_idx,
            sender_mac: &received.source_mac,
            origin: source.as_ref(),
            data_attributes: &received.data_attributes,
        };
        send_reject(&refused, dnet, RejectMessageReason::ADDRESSING_ERROR);
    }
}

/// Deliver or pass on a received reject, once the caller has applied it to
/// the routing table.
///
/// A reject with no DNET, or whose DADR is this router's own MAC on the
/// DNET's port, is addressed to this router. It goes no further, and the
/// router's own network-control consumer gets it (#1175), the way a
/// non-router hands one to its application side.
///
/// Any other reject is meant for the node its DNET/DADR names (Clause
/// 6.6.3.5), so it is routed like any other NPDU (Clause 6.5): handed to the
/// DADR, with SNET/SADR added, when the DNET is directly connected, or to the
/// next router with one hop spent. Nothing answers a reject, so one this
/// router cannot route is dropped: a DNET it has no route to, the global
/// broadcast DNET, or the arrival network, where the sender could have
/// reached the node itself.
pub(super) async fn route_received_reject(
    table: &Mutex<RouterTable>,
    send_txs: &[mpsc::Sender<SendRequest>],
    local: &LocalControl,
    ctx: &IngressContext,
) {
    let dnet = match ctx.npdu.destination.as_ref() {
        Some(dest) if !local.is_own_address(dest) => dest.network,
        _ => {
            local.deliver(ctx);
            return;
        }
    };
    if dnet == 0xFFFF || dnet == ctx.port_network {
        return;
    }
    let Some(route) = table.lock().await.lookup(dnet).cloned() else {
        return;
    };
    forward_unicast(
        send_txs,
        &route,
        ctx.port_network,
        &ctx.source_mac,
        ctx.npdu.clone(),
        ctx.port_idx,
        &ctx.data_attributes,
    );
}

#[cfg(test)]
#[path = "reject_tests.rs"]
mod tests;
