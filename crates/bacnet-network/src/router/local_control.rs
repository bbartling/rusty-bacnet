//! The router's own network-control consumer (#1175).
//!
//! Most network messages a router receives are for its routing table, and it
//! handles them inline. A Reject-Message-To-Network addressed to the router
//! itself also answers something the router's own side sent, so besides
//! updating the table it goes to the opt-in stream that
//! [`BACnetRouter::start_with_network_control_receiver`] returns. Its records
//! are the [`ReceivedNetworkControl`] a non-router
//! [`NetworkLayer`](crate::layer::NetworkLayer) hands its own consumer.

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

use bacnet_encoding::npdu::NpduAddress;
use bacnet_transport::port::TransportPort;
use bacnet_types::error::Error;
use bacnet_types::MacAddr;
use tokio::sync::mpsc;

use super::{control_policy, BACnetRouter, IngressContext, RouterPort};
use crate::layer::{
    next_ingress_sequence, AdmissionReceiver, AdmissionSender, ReceivedApdu, ReceivedNetworkControl,
};

/// Where network controls addressed to this router go.
#[derive(Default)]
pub(super) struct LocalControl {
    /// Each port's network number and own MAC, by port index.
    ports: Vec<(u16, MacAddr)>,
    /// The opted-in consumer, if any.
    tx: Option<AdmissionSender<ReceivedNetworkControl>>,
    /// Source of [`ReceivedNetworkControl::ingress_sequence`].
    ingress_sequence: Arc<AtomicU64>,
}

impl LocalControl {
    pub(super) fn new(
        ports: Vec<(u16, MacAddr)>,
        tx: Option<AdmissionSender<ReceivedNetworkControl>>,
        ingress_sequence: Arc<AtomicU64>,
    ) -> Self {
        Self {
            ports,
            tx,
            ingress_sequence,
        }
    }

    /// Whether `dest` is this router: its network is one of the router's
    /// ports and its MAC is the router's own MAC on that port.
    pub(super) fn is_own_address(&self, dest: &NpduAddress) -> bool {
        self.ports
            .iter()
            .any(|(network, mac)| *network == dest.network && *mac == dest.mac_address)
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
    /// Start like [`Self::start`], and also return the router's own
    /// network-control receiver (#1175).
    ///
    /// The receiver gets each Reject-Message-To-Network addressed to the
    /// router itself: one with no DNET, or whose DADR is the router's MAC on
    /// the port attached to that DNET. Such a reject still updates the routing
    /// table and is never relayed. Without this receiver, the table update is
    /// all that happens. Every other network message is still handled inline.
    ///
    /// Records match what a non-router
    /// [`NetworkLayer::enable_network_control_receiver`](crate::layer::NetworkLayer::enable_network_control_receiver)
    /// delivers, numbered from [`Self::network_control_ingress_sequence`]. The
    /// queue holds 256 controls, apart from the APDU queue. Admission never
    /// waits: a full or closed receiver drops the arriving control, and
    /// routing carries on.
    pub async fn start_with_network_control_receiver<T: TransportPort + 'static>(
        ports: Vec<RouterPort<T>>,
    ) -> Result<
        (
            Self,
            mpsc::Receiver<ReceivedApdu>,
            mpsc::Receiver<ReceivedNetworkControl>,
        ),
        Error,
    > {
        let (control_tx, control_rx, _) = AdmissionReceiver::channel(false);
        let (router, apdu_rx, _) = Self::start_dispatch_with_control(
            ports,
            false,
            Arc::new(control_policy::ControlGate::permissive()),
            Some(control_tx),
        )
        .await?;
        Ok((router, apdu_rx, control_rx))
    }

    /// Sequence assigned to the most recent control offered to the receiver
    /// from [`Self::start_with_network_control_receiver`], including one the
    /// receiver dropped. Saturates at `u64::MAX`.
    pub fn network_control_ingress_sequence(&self) -> u64 {
        self.network_control_ingress_sequence.load(Ordering::SeqCst)
    }
}
