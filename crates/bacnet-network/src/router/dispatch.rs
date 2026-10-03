//! Inbound dispatch: what the router does with each frame a port receives.
//!
//! Every port runs one [`PortDispatch`] task. A frame that decodes is either
//! a network message, which goes to [`dispatch_network_message`], or an APDU,
//! which its DNET sends to another port, to the local application queue, or
//! to both. Traffic the router cannot route draws a Reject-Message-To-Network
//! (see [`super::reject`]), and a DNET with no route also triggers one bounded
//! Who-Is-Router-To-Network solicitation.

use std::sync::atomic::AtomicU64;
use std::sync::Arc;

use bacnet_encoding::npdu::{decode_npdu, encode_npdu, Npdu, NpduDecodeError};
use bacnet_transport::port::{DataAttribute, ReceivedNpdu};
use bacnet_types::enums::{NetworkMessageType, RejectMessageReason};
use bacnet_types::MacAddr;
use bytes::{BufMut, BytesMut};
use tokio::sync::{mpsc, Mutex};
use tracing::warn;

use super::control_messages::handle_network_message;
use super::control_policy::ControlGate;
use super::forwarding::{forward_broadcast, forward_unicast};
use super::local_control::LocalControl;
use super::reject::{refuse_address_too_long, route_refusal, send_reject, Refused};
use super::{local_delivery, DiscoveryTracker, IngressContext, SendRequest};
use crate::layer::{is_group_delivery, link_source_fits, AdmissionSender, ReceivedApdu};
use crate::router_table::{ReachabilityStatus, RouteEntry, RouterTable};

/// One port's dispatch task, with what it shares with the rest of the router.
pub(super) struct PortDispatch {
    /// Shared routing table.
    pub table: Arc<Mutex<RouterTable>>,
    /// Bounded unknown-destination discovery (per-DNET coalescing).
    pub discovery: Arc<Mutex<DiscoveryTracker>>,
    /// RB-09 wire-control gate.
    pub control: Arc<ControlGate>,
    /// The router's own addresses and network-control consumer.
    pub local_control: Arc<LocalControl>,
    /// Count of NPDUs refused for an over-long address.
    pub address_length_drops: Arc<AtomicU64>,
    /// The local application receive queue.
    pub local_tx: AdmissionSender<ReceivedApdu>,
    /// Every port's send queue, by port index.
    pub send_txs: Arc<Vec<mpsc::Sender<SendRequest>>>,
    /// Dispatch index of this port.
    pub port_idx: usize,
    /// BACnet network number assigned to this port.
    pub port_network: u16,
    /// The router's own MAC on this port.
    pub local_mac: MacAddr,
}

impl PortDispatch {
    /// Dispatch every frame the port receives until its channel closes.
    pub(super) async fn run(self, mut rx: mpsc::Receiver<ReceivedNpdu>) {
        while let Some(received) = rx.recv().await {
            self.dispatch(received).await;
        }
    }

    async fn dispatch(&self, received: ReceivedNpdu) {
        if !link_source_fits(&received.source_mac, &self.address_length_drops) {
            return;
        }
        let npdu = match decode_npdu(received.npdu.clone()) {
            Ok(npdu) => npdu,
            Err(e @ NpduDecodeError::AddressTooLong { .. }) => {
                refuse_address_too_long(
                    &self.send_txs,
                    self.local_control.addresses(),
                    self.port_idx,
                    &received,
                    &e,
                    &self.address_length_drops,
                );
                return;
            }
            Err(e) => {
                warn!(error = %e, port = self.port_idx, "Router decode failed");
                return;
            }
        };

        if npdu.is_network_message {
            // RB-03 admission point: immutable ingress facts travel
            // together; RB-09 policy consumes them lock-free.
            // Controls never take the APDU reply path.
            let ctx = IngressContext {
                port_idx: self.port_idx,
                port_network: self.port_network,
                source_mac: received.source_mac.clone(),
                link_layer_group: received.link_layer_group,
                data_attributes: received.data_attributes.clone(),
                provenance: received.provenance,
                npdu,
            };
            dispatch_network_message(
                &self.table,
                &self.discovery,
                &self.send_txs,
                &ctx,
                &self.control,
                &self.local_control,
            )
            .await;
            return;
        }

        let Some(dest_net) = npdu.destination.as_ref().map(|dest| dest.network) else {
            let is_group = is_group_delivery(received.link_layer_group, None);
            self.deliver(received, npdu, is_group);
            return;
        };

        // Global broadcast: forward to all other ports, and deliver locally
        // as well.
        if dest_net == 0xFFFF {
            forward_broadcast(
                &self.send_txs,
                self.port_idx,
                self.port_network,
                &received.source_mac,
                &npdu,
                &received.data_attributes,
            );
            self.deliver(received, npdu, true);
            return;
        }

        let (route, reachability) = lookup_route(&self.table, dest_net).await;
        let refused = || {
            Refused::frame(
                &self.send_txs,
                self.local_control.addresses(),
                self.port_idx,
                &received,
                &npdu,
            )
        };
        let Some(route) = route else {
            refuse_unknown(&self.discovery, &refused(), dest_net).await;
            return;
        };
        // Check reachability before forwarding (spec 6.6.3.6)
        if let Some(reason) = route_refusal(reachability) {
            send_reject(&refused(), dest_net, reason);
            return;
        }

        if route.port_index == self.port_idx && route.directly_connected {
            let dest_mac = npdu
                .destination
                .as_ref()
                .map(|d| &d.mac_address[..])
                .unwrap_or(&[]);
            if dest_mac == &self.local_mac[..] {
                // DADR matches our MAC: deliver locally
                self.deliver(received, npdu, false);
                return;
            }
            // Remote broadcast to our network (DLEN=0): deliver locally AND
            // forward
            if dest_mac.is_empty() {
                self.deliver(received.clone(), npdu.clone(), true);
            }
        }
        forward_unicast(
            &self.send_txs,
            &route,
            self.port_network,
            &received.source_mac,
            npdu,
            self.port_idx,
            &received.data_attributes,
        );
    }

    /// Queue `npdu`'s APDU for the local application.
    fn deliver(&self, received: ReceivedNpdu, npdu: Npdu, is_group: bool) {
        let apdu = local_delivery::application(received, npdu, self.port_network, is_group);
        let _ = self.local_tx.try_send_apdu(apdu);
    }
}

/// RB-03 admission point for ingress network-layer messages.
///
/// Directed (DNET-addressed, non-global) controls are routed by their actual
/// destination first (Clauses 6.5.4 / 6.6.3.1) — uniformly for proprietary
/// and non-proprietary types — and only messages for our own ingress network
/// (or without a directed destination) fall through to local control
/// treatment. This keeps directed discovery, table, and congestion controls
/// off the local handler unless this router is their destination.
///
/// Never-routed controls (What-Is-Network-Number / Network-Number-Is,
/// Clauses 6.4.19–6.4.20) always take local treatment, where their
/// non-routed address restrictions are enforced. Reject-Message-To-Network
/// (Clause 6.6.3.5) also always takes local treatment: it updates the local
/// table, then either reaches `local` (when addressed to this router) or is
/// relayed toward the node it names, and is never answered with another
/// reject.
///
/// Network messages never enter the local APDU queue here. Directed-forward
/// paths mutate nothing and take no policy decision; APDUs never arrive here.
pub(super) async fn dispatch_network_message(
    table: &Arc<Mutex<RouterTable>>,
    discovery: &Arc<Mutex<DiscoveryTracker>>,
    send_txs: &[mpsc::Sender<SendRequest>],
    ctx: &IngressContext,
    control: &ControlGate,
    local: &LocalControl,
) {
    let msg_type = match ctx.npdu.message_type {
        Some(t) => t,
        None => return,
    };

    if msg_type == NetworkMessageType::WHAT_IS_NETWORK_NUMBER.to_raw()
        || msg_type == NetworkMessageType::NETWORK_NUMBER_IS.to_raw()
        || msg_type == NetworkMessageType::REJECT_MESSAGE_TO_NETWORK.to_raw()
    {
        handle_network_message(table, send_txs, ctx, control, local).await;
        return;
    }

    let directed_elsewhere = match ctx.npdu.destination.as_ref() {
        Some(dest) => dest.network != 0xFFFF && dest.network != ctx.port_network,
        None => false,
    };
    if !directed_elsewhere {
        handle_network_message(table, send_txs, ctx, control, local).await;
        return;
    }

    // Directed at another network: mirror the APDU destination logic
    // (lookup + touch, reachability, forward or reject). Controls are never
    // delivered to the local application queue.
    let dest_net = ctx
        .npdu
        .destination
        .as_ref()
        .map(|dest| dest.network)
        .unwrap_or(0);
    let (route, reachability) = lookup_route(table, dest_net).await;

    let refused = || Refused::control(send_txs, local.addresses(), ctx);
    let Some(route) = route else {
        refuse_unknown(discovery, &refused(), dest_net).await;
        return;
    };
    if let Some(reason) = route_refusal(reachability) {
        send_reject(&refused(), dest_net, reason);
        return;
    }
    forward_unicast(
        send_txs,
        &route,
        ctx.port_network,
        ctx.source_mac.as_slice(),
        ctx.npdu.clone(),
        ctx.port_idx,
        &ctx.data_attributes,
    );
}

/// The route to `dnet`, touched as used when the table has one, and the
/// reachability the table reports for `dnet`.
async fn lookup_route(
    table: &Mutex<RouterTable>,
    dnet: u16,
) -> (Option<RouteEntry>, Option<ReachabilityStatus>) {
    let mut tbl = table.lock().await;
    let route = tbl.lookup(dnet).cloned();
    let reachability = tbl.effective_reachability(dnet);
    if route.is_some() {
        tbl.touch(dnet);
    }
    (route, reachability)
}

/// Refuse traffic for a DNET with no route: bounded Who-Is discovery, then
/// the honest retryable reject (6.6.3.1/6.5). Coalesced per DNET; packets are
/// never buffered and nothing is retried inline.
async fn refuse_unknown(discovery: &Mutex<DiscoveryTracker>, refused: &Refused<'_>, dnet: u16) {
    let solicit = discovery.lock().await.should_solicit(dnet);
    if solicit {
        solicit_who_is(
            refused.send_txs,
            refused.port_idx,
            dnet,
            refused.data_attributes,
        );
    }
    send_reject(refused, dnet, RejectMessageReason::NOT_DIRECTLY_CONNECTED);
}

/// Broadcast a link-local Who-Is-Router-To-Network for `dnet` out all ports
/// except `ingress`, reusing the relay shape (no SNET/SADR, no DNET envelope).
fn solicit_who_is(
    send_txs: &[mpsc::Sender<SendRequest>],
    ingress: usize,
    dnet: u16,
    data_attributes: &[DataAttribute],
) {
    let mut payload = BytesMut::with_capacity(2);
    payload.put_u16(dnet);
    let npdu = Npdu {
        is_network_message: true,
        message_type: Some(NetworkMessageType::WHO_IS_ROUTER_TO_NETWORK.to_raw()),
        payload: payload.freeze(),
        ..Npdu::default()
    };
    let mut buf = BytesMut::with_capacity(8);
    if encode_npdu(&mut buf, &npdu).is_err() {
        return;
    }
    let frozen = buf.freeze();
    for (i, tx) in send_txs.iter().enumerate() {
        if i != ingress {
            let _ = tx.try_send(SendRequest::broadcast_with_attributes(
                frozen.clone(),
                data_attributes,
            ));
        }
    }
}
