//! The router's own network-control consumer (#1175).
//!
//! Most network messages a router receives are for its routing table, and it
//! handles them inline. A Reject-Message-To-Network addressed to the router
//! itself also answers something the router's own side sent, so besides
//! updating the table it goes to the opt-in stream that
//! [`RouterOptions::network_control_receiver`](super::RouterOptions::network_control_receiver)
//! asks for. Its records are the [`ReceivedNetworkControl`] a non-router
//! [`NetworkLayer`](crate::layer::NetworkLayer) hands its own consumer.

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

use bacnet_encoding::npdu::NpduAddress;

use super::{BACnetRouter, IngressContext};
use crate::layer::{next_ingress_sequence, AdmissionSender, ReceivedNetworkControl};

/// The router's own address on each port, by port index: the network the
/// port is attached to, with the router's MAC on that link.
#[derive(Debug, Default)]
pub(super) struct OwnAddresses(Vec<NpduAddress>);

impl OwnAddresses {
    pub(super) fn new(addresses: Vec<NpduAddress>) -> Self {
        Self(addresses)
    }

    /// Whether `address` is this router: the network of one of its ports,
    /// paired with the router's own MAC on that port.
    pub(super) fn contains(&self, address: &NpduAddress) -> bool {
        self.0.contains(address)
    }

    /// The port attached to `network`, if that network is one of the
    /// router's own.
    pub(super) fn port_on(&self, network: u16) -> Option<usize> {
        self.0.iter().position(|own| own.network == network)
    }
}

/// Where network controls addressed to this router go.
#[derive(Default)]
pub(super) struct LocalControl {
    /// The router's own address on each port.
    addresses: OwnAddresses,
    /// The opted-in consumer, if any.
    tx: Option<AdmissionSender<ReceivedNetworkControl>>,
    /// Source of [`ReceivedNetworkControl::ingress_sequence`].
    ingress_sequence: Arc<AtomicU64>,
}

impl LocalControl {
    pub(super) fn new(
        addresses: OwnAddresses,
        tx: Option<AdmissionSender<ReceivedNetworkControl>>,
        ingress_sequence: Arc<AtomicU64>,
    ) -> Self {
        Self {
            addresses,
            tx,
            ingress_sequence,
        }
    }

    /// The router's own address on each port, which also tells the reject
    /// path which networks are directly connected.
    pub(super) fn addresses(&self) -> &OwnAddresses {
        &self.addresses
    }

    /// Whether `dest` is this router: its network is one of the router's
    /// ports and its MAC is the router's own MAC on that port.
    pub(super) fn is_own_address(&self, dest: &NpduAddress) -> bool {
        self.addresses.contains(dest)
    }

    /// Offer the control in `ctx` to the consumer. Like the router's local
    /// APDU queue, a full or closed consumer drops the arriving control and
    /// never holds up routing.
    pub(super) fn deliver(&self, ctx: &IngressContext) {
        let Some(tx) = self.tx.as_ref() else {
            return;
        };
        let _ = tx.try_send(ReceivedNetworkControl {
            npdu: ctx.npdu.clone(),
            source_mac: ctx.source_mac.clone(),
            link_layer_group: ctx.link_layer_group,
            data_attributes: ctx.data_attributes.clone(),
            provenance: ctx.provenance,
            ingress_sequence: next_ingress_sequence(&self.ingress_sequence),
        });
    }
}

impl BACnetRouter {
    /// Sequence assigned to the most recent control offered to the receiver
    /// from [`RouterOptions::network_control_receiver`](super::RouterOptions::network_control_receiver)
    /// or [`RouterOptions::network_control_receiver_with_admission`](super::RouterOptions::network_control_receiver_with_admission),
    /// including one the receiver dropped. Saturates at `u64::MAX`.
    pub fn network_control_ingress_sequence(&self) -> u64 {
        self.network_control_ingress_sequence.load(Ordering::SeqCst)
    }
}
