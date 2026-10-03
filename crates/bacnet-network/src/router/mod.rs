//! BACnet half-router — forwards APDUs between BACnet networks.
//!
//! A BACnet router (ASHRAE 135-2020 Clause 6.6) sits on several BACnet
//! networks at once and relays messages among them, rewriting the NPDU
//! source/destination fields and decrementing the hop count as it goes.
//!
//! This implementation supports:
//! - Forwarding APDUs between directly-connected networks
//! - Who-Is-Router-To-Network / I-Am-Router-To-Network messages
//! - Reject-Message-To-Network for unknown routes
//! - Learned routes from I-Am-Router-To-Network announcements
//!
//! Local application delivery follows the shared
//! [receive-queue contract](crate::layer#receive-queue-admission), independently
//! of forwarding and inline network-message handling.
//!
//! # Routing-claim trust model (RB-06)
//!
//! Classic BACnet routing claims are unauthenticated: an ingress port, next-hop
//! MAC or advertised network is not proof that a peer is authorized to control
//! that route. These local mitigations do not prevent route poisoning or
//! authenticate a claim (Clauses 6.4 and 6.6.3):
//! - Direct routes cannot be overwritten by learning, changed by rejects, or
//!   changed by Initialize-Routing-Table management updates.
//! - Standard convergence applies 6.6.3.2 last-wins immediately: each new
//!   I-Am-Router / Init-ACK advertisement updates routing information, with
//!   flap warnings retained. Same-port refreshes and absent learning stay
//!   immediate; I-Could-Be-Router remains absent-only.
//! - Hardened convergence (`RouterTable::new_hardened`, explicit opt-in only)
//!   holds cross-port learned moves for a second same-(network, port) claim
//!   within 60s inclusive. Repeats in separate messages suffice; duplicates in
//!   one message cannot corroborate. The old route forwards while pending.
//!   Alternation resets the slot; single-shot advertisers need the 60s reaper
//!   plus a fresh claim. Corroboration is dampening, not identity assurance.
//! - Initialize-Routing-Table updates are management writes (6.4.7/6.6.3.8):
//!   nonzero Port ID replaces/appends the learned entry, Port ID 0 purges it,
//!   immediately in wire order. They never create/alter direct routes. Wire
//!   controls pass [`control_policy::ControlGate`] (RB-09); direct immunity
//!   stays safety scoping, not auth. LOCAL table calls bypass policy.
//! - A query (Number of Ports 0) never mutates and answers with the complete
//!   table in ascending-DNET bounded portions (6.6.3.9); wire Port IDs are
//!   `port_index + 1` (0 stays the purge trigger).
//! - Hardened pending holds one challenger per learned network (bounded by live
//!   learned routes). Slots expire lazily on the next claim plus the 60s aging
//!   reaper; apply/refresh/removal/aging/direct/manual edits clear the slot.
//! - Freshness is split: `last_seen` (control confirmation) drives 300s expiry;
//!   `last_used` (forwarding use) never extends it. Busy/Available touch
//!   neither. Traffic no longer pins a dead route past the rescue.
//! - Unknown DNETs solicit once per 5s per DNET (coalesced, max 256 pending,
//!   30s entry age, reserved never solicited) then fail the caller with
//!   NOT_DIRECTLY_CONNECTED (6.6.3.1/6.5 retryable); packets are never buffered.
//!   `stop` cancels pending discovery.
//! - Disconnect never removes routes (PTP unimplemented). Reject transitions
//!   are dampened per (ingress port, network) with a 30s hold-down; no-op
//!   rejects never extend busy deadlines. [`RouterTable::claim_snapshot`]
//!   stays count-only saturating and never affects decisions.

mod local_delivery;

use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use bacnet_encoding::npdu::{decode_npdu, encode_npdu, Npdu, NpduAddress, NpduDecodeError};
use bacnet_transport::port::{DataAttribute, TransportPort};
use bacnet_types::enums::{NetworkMessageType, RejectMessageReason};
use bacnet_types::error::Error;
use bacnet_types::MacAddr;
use bytes::{BufMut, Bytes, BytesMut};
use tokio::sync::{mpsc, Mutex};
use tokio::task::JoinHandle;
use tracing::{debug, warn};

use crate::layer::{is_group_delivery, AdmissionReceiver, QueueAdmissionCounters, ReceivedApdu};
use crate::layer::{link_source_fits, AdmissionSender, ReceivedNetworkControl};
use crate::router_table::RouterTable;
use bacnet_transport::port::TransportProvenance;

mod control_messages;
pub mod control_policy;
mod forwarding;
mod local_control;
mod options;
mod reject;

use control_messages::handle_network_message;
pub use control_policy::{ControlAuthContext, ControlAuthorizer, ControlClass};
pub use control_policy::{ControlDecisionCounters, ControlGate, ControlPolicy};
pub use control_policy::{ControlServiceCounters, ControlTrust};
use forwarding::{forward_broadcast, forward_unicast};
use local_control::{LocalControl, OwnAddresses};
pub use options::{LocalApduReceiver, NetworkControlReceiver, RouterOptions, StartedRouter};
use reject::{refuse_address_too_long, route_refusal, send_reject, Refused};

/// A send request to be forwarded on a port.
#[derive(Debug)]
enum SendRequest {
    Unicast {
        npdu: Bytes,
        mac: MacAddr,
        data_attributes: Vec<DataAttribute>,
    },
    Broadcast {
        npdu: Bytes,
        data_attributes: Vec<DataAttribute>,
    },
}

impl SendRequest {
    fn broadcast(npdu: Bytes) -> Self {
        Self::broadcast_with_attributes(npdu, &[])
    }

    /// Ingress-triggered unicast: carries the ingress data attributes instead
    /// of silently dropping them (RB-03). Locally-originated messages with no
    /// ingress attributes pass an empty slice.
    fn unicast_with_attributes(
        npdu: Bytes,
        mac: MacAddr,
        data_attributes: &[DataAttribute],
    ) -> Self {
        Self::Unicast {
            npdu,
            mac,
            data_attributes: data_attributes.to_vec(),
        }
    }

    /// Ingress-triggered broadcast: carries the ingress data attributes
    /// instead of silently dropping them (RB-03). Locally-originated
    /// messages with no ingress attributes use [`Self::broadcast`].
    fn broadcast_with_attributes(npdu: Bytes, data_attributes: &[DataAttribute]) -> Self {
        Self::Broadcast {
            npdu,
            data_attributes: data_attributes.to_vec(),
        }
    }
}

/// Bounded unknown-destination discovery (RB-06, Clauses 6.5/6.6.3.1).
///
/// Per-DNET single inflight Who-Is solicitation: simultaneous unknowns coalesce
/// to one broadcast, rate-limited to one per DNET per 5s, entries expire after
/// 30s via the aging reaper, at most 256 pending DNETs, reserved never
/// solicited. The caller still fails with NOT_DIRECTLY_CONNECTED (honest
/// retryable); packets are never buffered and no per-packet retries occur.
/// `cancel` (via [`BACnetRouter::stop`]) drops all pending discovery.
const DISCOVERY_COOLDOWN: Duration = Duration::from_secs(5);
const DISCOVERY_MAX_AGE: Duration = Duration::from_secs(30);
const DISCOVERY_MAX_PENDING: usize = 256;

#[derive(Debug, Default)]
pub(crate) struct DiscoveryTracker {
    last_solicited: HashMap<u16, Instant>,
    cancelled: bool,
}

impl DiscoveryTracker {
    /// Decide whether an unknown `dnet` should solicit now; records it if so.
    pub(crate) fn should_solicit_at(&mut self, dnet: u16, now: Instant) -> bool {
        if self.cancelled || dnet == 0 || dnet == 0xFFFF {
            return false;
        }
        if let Some(last) = self.last_solicited.get(&dnet) {
            if now.duration_since(*last) < DISCOVERY_COOLDOWN {
                return false;
            }
        } else if self.last_solicited.len() >= DISCOVERY_MAX_PENDING {
            return false;
        }
        self.last_solicited.insert(dnet, now);
        true
    }

    /// Wall-clock wrapper for dispatch paths.
    pub(crate) fn should_solicit(&mut self, dnet: u16) -> bool {
        self.should_solicit_at(dnet, Instant::now())
    }

    /// Reap entries older than 30s; returns the reaped DNETs ascending.
    pub(crate) fn expire_at(&mut self, now: Instant) -> Vec<u16> {
        let mut out: Vec<u16> = self
            .last_solicited
            .iter()
            .filter(|(_, last)| now.duration_since(**last) > DISCOVERY_MAX_AGE)
            .map(|(net, _)| *net)
            .collect();
        out.sort_unstable();
        for net in &out {
            self.last_solicited.remove(net);
        }
        out
    }

    /// Cancel all pending discovery (router stop).
    pub(crate) fn cancel(&mut self) {
        self.cancelled = true;
        self.last_solicited.clear();
    }

    #[cfg(test)]
    pub(crate) fn len(&self) -> usize {
        self.last_solicited.len()
    }

    #[cfg(test)]
    pub(crate) fn is_cancelled(&self) -> bool {
        self.cancelled
    }
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

/// Immutable ingress facts carried to the network-message admission point
/// ([`dispatch_network_message`] / `handle_network_message`).
///
/// This is a plain record of what arrived, free of trust assertions: ingress port
/// identity, the immediate link peer (`source_mac`), link-layer group flag,
/// data-link attributes, and the decoded NPDU envelope (source/destination,
/// hop count, message type, vendor ID). It asserts no provenance or trust —
/// a claimed SNET/SADR is carried, never verified here.
///
/// RB-07 threads [`TransportProvenance`] here; RB-09 [`control_policy`]
/// consumes it at the same admission point for protected-control decisions.
#[derive(Debug, Clone)]
pub(super) struct IngressContext {
    /// Dispatch index of the ingress port.
    pub port_idx: usize,
    /// BACnet network number assigned to the ingress port.
    pub port_network: u16,
    /// Immediate link peer that sent the frame (SA), not the routed origin.
    pub source_mac: MacAddr,
    /// Whether the frame arrived via a data-link multicast/broadcast.
    pub link_layer_group: bool,
    /// Data-link attributes supplied with the frame, if any.
    pub data_attributes: Vec<DataAttribute>,
    /// Honest transport + origin provenance, immutable by value (RB-07).
    /// Threaded, never decided on here.
    pub provenance: TransportProvenance,
    /// Decoded NPDU, including envelope (source/destination, hop count,
    /// message type, vendor ID) and control payload.
    pub npdu: Npdu,
}

#[cfg(test)]
impl IngressContext {
    /// In-memory test ingress: link-broadcast delivery with no attributes.
    pub(super) fn test_local(
        port_idx: usize,
        port_network: u16,
        source_mac: &[u8],
        npdu: Npdu,
    ) -> Self {
        Self {
            port_idx,
            port_network,
            source_mac: MacAddr::from_slice(source_mac),
            link_layer_group: true,
            data_attributes: Vec::new(),
            provenance: TransportProvenance::unverified(),
            npdu,
        }
    }

    /// In-memory test ingress with explicit provenance (RB-07).
    #[cfg(test)]
    pub(super) fn test_local_with_provenance(
        port_idx: usize,
        port_network: u16,
        source_mac: &[u8],
        npdu: Npdu,
        provenance: TransportProvenance,
    ) -> Self {
        Self {
            port_idx,
            port_network,
            source_mac: MacAddr::from_slice(source_mac),
            link_layer_group: true,
            data_attributes: Vec::new(),
            provenance,
            npdu,
        }
    }
}

/// A router port: a transport bound to a specific BACnet network number.
pub struct RouterPort<T: TransportPort> {
    /// The transport for this port.
    pub transport: T,
    /// The network number assigned to this port.
    pub network_number: u16,
}

/// BACnet router connecting multiple networks.
///
/// The router holds multiple ports, each bound to a different BACnet network.
/// When an NPDU arrives on one port with a destination network that maps to
/// another port, the router forwards the message.
/// See the [receive-queue contract](crate::layer#receive-queue-admission) for
/// raw/tracked local receivers, admission limits, counters and lifecycle.
pub struct BACnetRouter {
    /// Shared routing table.
    table: Arc<Mutex<RouterTable>>,
    /// Bounded unknown-destination discovery (per-DNET coalescing).
    discovery: Arc<Mutex<DiscoveryTracker>>,
    /// RB-09 wire-control gate (permissive default, hardened opt-in).
    control: Arc<control_policy::ControlGate>,
    /// Dispatch tasks (one per port).
    dispatch_tasks: Vec<JoinHandle<()>>,
    /// Sender tasks (one per port, owns the transport for outgoing messages).
    sender_tasks: Vec<JoinHandle<()>>,
    /// Background task that purges stale learned routes.
    aging_task: Option<JoinHandle<()>>,
    /// NPDUs refused for a link-layer source MAC, DLEN or SLEN past
    /// `NpduAddress::MAX_MAC_LEN`.
    address_length_drops: Arc<AtomicU64>,
    /// Last sequence given to a control for the router's own consumer.
    network_control_ingress_sequence: Arc<AtomicU64>,
}

impl BACnetRouter {
    /// Create and start a router from a list of ports, set up as `options`
    /// asks (#1220).
    ///
    /// Returns the router with its local APDU receiver, for messages without
    /// a remote destination or for which this router is the final hop, plus
    /// the network-control receiver when the options ask for it.
    /// [`RouterOptions::new`] is the plain router; see [`RouterOptions`] for
    /// the tracked APDU receiver, the wire-control policy and the
    /// network-control receiver, which combine freely.
    ///
    /// Fails if two ports share a network number or a transport fails to
    /// start.
    pub async fn start<T, A, C>(
        ports: Vec<RouterPort<T>>,
        options: RouterOptions<A, C>,
    ) -> Result<StartedRouter<A, C>, Error>
    where
        T: TransportPort + 'static,
        A: LocalApduReceiver,
        C: NetworkControlReceiver,
    {
        let (control_tx, network_control) = if options.wants_network_control() {
            let (tx, rx, counters) = AdmissionReceiver::channel(C::TRACKED);
            (Some(tx), Some(C::from_queue(rx, counters)))
        } else {
            (None, None)
        };
        let gate = Arc::new(options.control_gate());
        let (router, rx, counters) =
            Self::start_dispatch(ports, A::TRACKED, gate, control_tx).await?;
        Ok(StartedRouter {
            router,
            apdus: A::from_queue(rx, counters),
            network_control,
        })
    }

    /// Count-only RB-09 decision totals (allow/deny/policy-deny per class).
    pub fn control_snapshot(&self) -> control_policy::ControlDecisionCounters {
        self.control.snapshot()
    }

    /// NPDUs refused on any port since start because an address in them was
    /// past [`NpduAddress::MAX_MAC_LEN`](bacnet_encoding::npdu::NpduAddress::MAX_MAC_LEN):
    /// their DLEN or SLEN (#1141), or the link-layer source MAC the port's
    /// transport reported (#1198). Saturates at `u64::MAX`.
    ///
    /// Such an NPDU is neither forwarded nor delivered locally, and a network
    /// message in it changes no route. When its DLEN or SLEN is the long one
    /// and it names a specific DNET, the router also answers the sender with
    /// Reject-Message-To-Network reason 6, `ADDRESSING_ERROR` (Clause 6.4.4),
    /// the way it rejects a DNET it cannot reach. A global broadcast, or an
    /// NPDU without a DNET, is only dropped. So is a frame from an over-long
    /// link-layer source MAC: that is a fault in the transport, not in the
    /// NPDU, and the router sends nothing back to such a MAC. No built-in
    /// transport reports one.
    pub fn address_length_drops(&self) -> u64 {
        self.address_length_drops.load(Ordering::Relaxed)
    }

    async fn start_dispatch<T: TransportPort + 'static>(
        mut ports: Vec<RouterPort<T>>,
        track_depth: bool,
        control: Arc<control_policy::ControlGate>,
        network_control: Option<AdmissionSender<ReceivedNetworkControl>>,
    ) -> Result<(Self, mpsc::Receiver<ReceivedApdu>, QueueAdmissionCounters), Error> {
        let mut table = RouterTable::new();

        // Reject duplicate network numbers
        {
            let mut seen = std::collections::HashSet::new();
            for port in &ports {
                if !seen.insert(port.network_number) {
                    return Err(Error::Encoding(format!(
                        "Duplicate network number {} in router ports",
                        port.network_number
                    )));
                }
            }
        }

        // Register directly-connected networks
        for (idx, port) in ports.iter().enumerate() {
            table.add_direct(port.network_number, idx);
        }

        let table = Arc::new(Mutex::new(table));
        let discovery = Arc::new(Mutex::new(DiscoveryTracker::default()));
        let (local_tx, local_rx, counters) = AdmissionReceiver::channel(track_depth);

        // Start each transport, set up send channels
        let mut port_receivers = Vec::new();
        let mut send_txs: Vec<mpsc::Sender<SendRequest>> = Vec::new();
        let mut sender_tasks = Vec::new();
        let mut port_networks = Vec::new();
        let mut port_local_macs = Vec::new();

        for port in &mut ports {
            let rx = port.transport.start().await?;
            port_receivers.push(rx);
            port_networks.push(port.network_number);
            port_local_macs.push(MacAddr::from_slice(port.transport.local_mac()));
        }

        // Move transports into sender tasks
        for port in ports {
            let (send_tx, mut send_rx) = mpsc::channel::<SendRequest>(256);
            send_txs.push(send_tx);

            let transport = port.transport;
            let task = tokio::spawn(async move {
                while let Some(req) = send_rx.recv().await {
                    match req {
                        SendRequest::Unicast {
                            npdu,
                            mac,
                            data_attributes,
                        } => {
                            if let Err(e) = transport
                                .send_unicast_with_data_attributes(&npdu, &mac, &data_attributes)
                                .await
                            {
                                warn!(error = %e, "Router send_unicast failed");
                            }
                        }
                        SendRequest::Broadcast {
                            npdu,
                            data_attributes,
                        } => {
                            if let Err(e) = transport
                                .send_broadcast_with_data_attributes(&npdu, &data_attributes)
                                .await
                            {
                                warn!(error = %e, "Router send_broadcast failed");
                            }
                        }
                    }
                }
            });
            sender_tasks.push(task);
        }

        let send_txs = Arc::new(send_txs);

        // Announce I-Am-Router-To-Network on each port listing networks reachable via other ports.
        for (port_idx, tx) in send_txs.iter().enumerate() {
            let other_networks: Vec<u16> = port_networks
                .iter()
                .enumerate()
                .filter(|(idx, _)| *idx != port_idx)
                .map(|(_, net)| *net)
                .collect();

            if other_networks.is_empty() {
                continue;
            }

            let mut payload = BytesMut::with_capacity(other_networks.len() * 2);
            for net in &other_networks {
                payload.put_u16(*net);
            }

            let payload_len = payload.len();
            let response = Npdu {
                is_network_message: true,
                message_type: Some(NetworkMessageType::I_AM_ROUTER_TO_NETWORK.to_raw()),
                payload: payload.freeze(),
                ..Npdu::default()
            };

            let mut buf = BytesMut::with_capacity(8 + payload_len);
            if let Err(e) = encode_npdu(&mut buf, &response) {
                warn!("Failed to encode I-Am-Router NPDU: {e}");
                continue;
            }

            if let Err(e) = tx.try_send(SendRequest::broadcast(buf.freeze())) {
                warn!(%e, "Router dropped I-Am-Router announcement: output channel full");
            }
        }

        let mut dispatch_tasks = Vec::new();
        let address_length_drops = Arc::new(AtomicU64::new(0));
        let network_control_ingress_sequence = Arc::new(AtomicU64::new(0));
        let local_control = Arc::new(LocalControl::new(
            OwnAddresses::new(
                port_networks
                    .iter()
                    .zip(&port_local_macs)
                    .map(|(&network, mac)| NpduAddress {
                        network,
                        mac_address: mac.clone(),
                    })
                    .collect(),
            ),
            network_control,
            Arc::clone(&network_control_ingress_sequence),
        ));

        for (port_idx, mut rx) in port_receivers.into_iter().enumerate() {
            let table = Arc::clone(&table);
            let discovery = Arc::clone(&discovery);
            let control = Arc::clone(&control);
            let local_control = Arc::clone(&local_control);
            let address_length_drops = Arc::clone(&address_length_drops);
            let local_tx = local_tx.clone();
            let send_txs = Arc::clone(&send_txs);
            let port_network = port_networks[port_idx];
            let local_mac = port_local_macs[port_idx].clone();

            let task = tokio::spawn(async move {
                while let Some(received) = rx.recv().await {
                    if !link_source_fits(&received.source_mac, &address_length_drops) {
                        continue;
                    }
                    match decode_npdu(received.npdu.clone()) {
                        Ok(npdu) => {
                            if npdu.is_network_message {
                                // RB-03 admission point: immutable ingress facts travel
                                // together; RB-09 policy consumes them lock-free.
                                // Controls never take the APDU reply path.
                                let ctx = IngressContext {
                                    port_idx,
                                    port_network,
                                    source_mac: received.source_mac.clone(),
                                    link_layer_group: received.link_layer_group,
                                    data_attributes: received.data_attributes.clone(),
                                    provenance: received.provenance,
                                    npdu,
                                };
                                dispatch_network_message(
                                    &table,
                                    &discovery,
                                    &send_txs,
                                    &ctx,
                                    &control,
                                    &local_control,
                                )
                                .await;
                                continue;
                            }

                            if let Some(ref dest) = npdu.destination {
                                let dest_net = dest.network;

                                // Global broadcast — forward to all other ports
                                if dest_net == 0xFFFF {
                                    forward_broadcast(
                                        &send_txs,
                                        port_idx,
                                        port_network,
                                        &received.source_mac,
                                        &npdu,
                                        &received.data_attributes,
                                    );

                                    // Deliver locally as well
                                    let apdu = local_delivery::application(
                                        received,
                                        npdu,
                                        port_network,
                                        true,
                                    );
                                    let _ = local_tx.try_send_apdu(apdu);
                                    continue;
                                }

                                // Route lookup for destination network
                                let (route, reachability) = {
                                    let mut tbl = table.lock().await;
                                    let route = tbl.lookup(dest_net).cloned();
                                    let reachability = tbl.effective_reachability(dest_net);
                                    if route.is_some() {
                                        tbl.touch(dest_net);
                                    }
                                    (route, reachability)
                                };

                                if let Some(route) = route {
                                    // Check reachability before forwarding (spec 6.6.3.6)
                                    if let Some(reason) = route_refusal(reachability) {
                                        let refused = Refused::frame(
                                            &send_txs,
                                            local_control.addresses(),
                                            port_idx,
                                            &received,
                                            &npdu,
                                        );
                                        send_reject(&refused, dest_net, reason);
                                        continue;
                                    }
                                    if route.port_index == port_idx && route.directly_connected {
                                        let dest_mac = npdu
                                            .destination
                                            .as_ref()
                                            .map(|d| &d.mac_address[..])
                                            .unwrap_or(&[]);
                                        if dest_mac == &local_mac[..] {
                                            // DADR matches our MAC: deliver locally
                                            let apdu = local_delivery::application(
                                                received,
                                                npdu,
                                                port_network,
                                                false,
                                            );
                                            let _ = local_tx.try_send_apdu(apdu);
                                        } else {
                                            // Remote broadcast to our network (DLEN=0):
                                            // deliver locally AND forward
                                            if dest_mac.is_empty() {
                                                let apdu = local_delivery::application(
                                                    received.clone(),
                                                    npdu.clone(),
                                                    port_network,
                                                    true,
                                                );
                                                let _ = local_tx.try_send_apdu(apdu);
                                            }
                                            forward_unicast(
                                                &send_txs,
                                                &route,
                                                port_network,
                                                &received.source_mac,
                                                npdu,
                                                port_idx,
                                                &received.data_attributes,
                                            );
                                        }
                                    } else {
                                        forward_unicast(
                                            &send_txs,
                                            &route,
                                            port_network,
                                            &received.source_mac,
                                            npdu,
                                            port_idx,
                                            &received.data_attributes,
                                        );
                                    }
                                } else {
                                    // Unknown: bounded Who-Is discovery, then honest
                                    // retryable reject (6.6.3.1/6.5). Coalesced per
                                    // DNET; packets never buffered, no retries.
                                    let solicit = {
                                        let mut disc = discovery.lock().await;
                                        disc.should_solicit(dest_net)
                                    };
                                    if solicit {
                                        solicit_who_is(
                                            &send_txs,
                                            port_idx,
                                            dest_net,
                                            &received.data_attributes,
                                        );
                                    }
                                    send_reject(
                                        &Refused::frame(
                                            &send_txs,
                                            local_control.addresses(),
                                            port_idx,
                                            &received,
                                            &npdu,
                                        ),
                                        dest_net,
                                        RejectMessageReason::NOT_DIRECTLY_CONNECTED,
                                    );
                                }
                            } else {
                                let is_group = is_group_delivery(received.link_layer_group, None);
                                let apdu = local_delivery::application(
                                    received,
                                    npdu,
                                    port_network,
                                    is_group,
                                );
                                let _ = local_tx.try_send_apdu(apdu);
                            }
                        }
                        Err(e @ NpduDecodeError::AddressTooLong { .. }) => {
                            refuse_address_too_long(
                                &send_txs,
                                local_control.addresses(),
                                port_idx,
                                &received,
                                &e,
                                &address_length_drops,
                            );
                        }
                        Err(e) => {
                            warn!(error = %e, port = port_idx, "Router decode failed");
                        }
                    }
                }
            });

            dispatch_tasks.push(task);
        }

        // Periodically purge stale learned routes, hardened pending slots and
        // discovery entries. `last_used` never extends `last_seen` expiry.
        let aging_table = Arc::clone(&table);
        let aging_discovery = Arc::clone(&discovery);
        let aging_task = tokio::spawn(async move {
            let mut interval = tokio::time::interval(Duration::from_secs(60));
            let max_age = Duration::from_secs(300); // 5 minutes
            loop {
                interval.tick().await;
                let now = Instant::now();
                let mut tbl = aging_table.lock().await;
                let purged = tbl.purge_stale_at(now, max_age);
                tbl.clear_expired_busy();
                let expired_pending = tbl.expire_pending_at(now);
                drop(tbl);
                let mut disc = aging_discovery.lock().await;
                let expired_discovery = disc.expire_at(now);
                drop(disc);
                for net in purged {
                    debug!(network = net, "Purged stale route");
                }
                for net in expired_pending {
                    debug!(network = net, "Expired hardened pending challenger");
                }
                for net in expired_discovery {
                    debug!(network = net, "Expired discovery solicitation");
                }
            }
        });

        Ok((
            Self {
                table,
                discovery,
                control,
                dispatch_tasks,
                sender_tasks,
                aging_task: Some(aging_task),
                address_length_drops,
                network_control_ingress_sequence,
            },
            local_rx,
            counters,
        ))
    }

    /// Get a reference to the routing table.
    pub fn table(&self) -> &Arc<Mutex<RouterTable>> {
        &self.table
    }

    /// Stop the router.
    ///
    /// Aborts and awaits dispatch, sender and aging tasks without waiting for
    /// the local application consumer, even with a full queue. Queued local
    /// APDUs remain drainable, retaining their reply senders until consumed or
    /// the receiver is dropped. Stop is not an admission drop and does not clear
    /// depth/high-water/drop totals. See the
    /// [receive-queue contract](crate::layer#receive-queue-admission).
    pub async fn stop(&mut self) {
        for task in self.dispatch_tasks.drain(..) {
            task.abort();
            let _ = task.await;
        }
        for task in self.sender_tasks.drain(..) {
            task.abort();
            let _ = task.await;
        }
        if let Some(task) = self.aging_task.take() {
            task.abort();
            let _ = task.await;
        }
        // Cancel pending unknown-destination discovery so no further
        // solicitation is emitted and coalesced waiters observe shutdown.
        self.discovery.lock().await.cancel();
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
async fn dispatch_network_message(
    table: &Arc<Mutex<RouterTable>>,
    discovery: &Arc<Mutex<DiscoveryTracker>>,
    send_txs: &[mpsc::Sender<SendRequest>],
    ctx: &IngressContext,
    control: &control_policy::ControlGate,
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
    let (route, reachability) = {
        let mut tbl = table.lock().await;
        let route = tbl.lookup(dest_net).cloned();
        let reachability = tbl.effective_reachability(dest_net);
        if route.is_some() {
            tbl.touch(dest_net);
        }
        (route, reachability)
    };

    if let Some(route) = route {
        if let Some(reason) = route_refusal(reachability) {
            let refused = Refused::control(send_txs, local.addresses(), ctx);
            send_reject(&refused, dest_net, reason);
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
    } else {
        // Unknown directed control: same bounded discovery as APDUs, then
        // the honest retryable reject. Never buffered, never retried inline.
        let solicit = {
            let mut disc = discovery.lock().await;
            disc.should_solicit(dest_net)
        };
        if solicit {
            solicit_who_is(send_txs, ctx.port_idx, dest_net, &ctx.data_attributes);
        }
        send_reject(
            &Refused::control(send_txs, local.addresses(), ctx),
            dest_net,
            RejectMessageReason::NOT_DIRECTLY_CONNECTED,
        );
    }
}

#[cfg(test)]
mod admission_tests;
#[cfg(test)]
mod busy_scope_tests;
#[cfg(test)]
mod claim_tests;
#[cfg(test)]
mod envelope_control_tests;
#[cfg(test)]
mod envelope_discovery_tests;
#[cfg(test)]
mod envelope_harness;
#[cfg(test)]
mod ingress_harness;
#[cfg(test)]
mod init_routing_table_tests;
#[cfg(test)]
mod rb06_convergence_tests;
#[cfg(test)]
mod rb09_control_policy_tests;
#[cfg(test)]
mod tests;
