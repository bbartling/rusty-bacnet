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
use tracing::warn;

use super::forwarding::forward_unicast;
use super::local_control::LocalControl;
use super::{IngressContext, SendRequest};
use crate::layer::count_address_length_drop;
use crate::router_table::{ReachabilityStatus, RouterTable};

/// What a reject needs to know about the NPDU it refuses.
pub(super) struct Refused<'a> {
    /// Send queue of the port the refused NPDU arrived on.
    pub send_tx: &'a mpsc::Sender<SendRequest>,
    /// Network number of the port the refused NPDU arrived on.
    pub port_network: u16,
    /// Link-layer source of the refused NPDU: the node that handed it to us.
    pub sender_mac: &'a [u8],
    /// The refused NPDU's SNET/SADR, present when a router relayed it.
    pub origin: Option<&'a NpduAddress>,
    /// Ingress data attributes, which travel with the reject (RB-03).
    pub data_attributes: &'a [DataAttribute],
}

impl<'a> Refused<'a> {
    /// A decoded NPDU refused on the port `send_tx` serves, which is attached
    /// to `port_network`.
    pub(super) fn frame(
        send_tx: &'a mpsc::Sender<SendRequest>,
        port_network: u16,
        received: &'a ReceivedNpdu,
        npdu: &'a Npdu,
    ) -> Self {
        Self {
            send_tx,
            port_network,
            sender_mac: &received.source_mac,
            origin: npdu.source.as_ref(),
            data_attributes: &received.data_attributes,
        }
    }

    /// A network message refused at the control admission point.
    pub(super) fn control(
        send_txs: &'a [mpsc::Sender<SendRequest>],
        ctx: &'a IngressContext,
    ) -> Self {
        Self {
            send_tx: &send_txs[ctx.port_idx],
            port_network: ctx.port_network,
            sender_mac: &ctx.source_mac,
            origin: ctx.npdu.source.as_ref(),
            data_attributes: &ctx.data_attributes,
        }
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
/// A refused NPDU that carries SNET/SADR came through another router, and its
/// originator sits on that remote network. The reject names the originator
/// as its DNET/DADR, starts with a full hop count, and goes back out the
/// arrival port to the link sender, the router that relayed the NPDU and so
/// knows the way back. An NPDU without SNET/SADR came from the arrival link
/// itself, and the reject is a plain local unicast to its sender.
///
/// An SNET equal to the arrival port's own network puts the originator on the
/// arrival link too (#1174). A router reaches a node on a directly connected
/// network by dropping DNET/DADR and sending to that node's MAC (Clause
/// 6.5.4), so the reject is a local unicast to the SADR. Sent to the link
/// sender with a DNET instead, it would be lost: a non-router discards an NPDU
/// that names a remote DNET (Clause 6.5.2.1), and a router would have to send
/// it back out the port it arrived on.
///
/// Locally generated, but ingress-triggered: the caller's data attributes
/// travel with the reject instead of being silently dropped (RB-03).
pub(super) fn send_reject(
    refused: &Refused<'_>,
    rejected_network: u16,
    reason: RejectMessageReason,
) {
    let mut payload = BytesMut::with_capacity(3);
    payload.put_u8(reason.to_raw());
    payload.put_u16(rejected_network);

    let (destination, link_mac) = match refused.origin {
        Some(origin) if origin.network == refused.port_network => (None, &origin.mac_address[..]),
        Some(origin) => (Some(origin.clone()), refused.sender_mac),
        None => (None, refused.sender_mac),
    };
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

    if let Err(e) = refused
        .send_tx
        .try_send(SendRequest::unicast_with_attributes(
            buf.freeze(),
            MacAddr::from_slice(link_mac),
            refused.data_attributes,
        ))
    {
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
    send_tx: &mpsc::Sender<SendRequest>,
    port_idx: usize,
    port_network: u16,
    received: &ReceivedNpdu,
    refused: &NpduDecodeError,
    drops: &AtomicU64,
) {
    warn!(error = %refused, port = port_idx, "Router refused an NPDU");
    count_address_length_drop(drops);
    let NpduDecodeError::AddressTooLong { dnet, source, .. } = refused else {
        return;
    };
    if let Some(dnet) = dnet.filter(|&dnet| dnet != 0xFFFF) {
        let refused = Refused {
            send_tx,
            port_network,
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
