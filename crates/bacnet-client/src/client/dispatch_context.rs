//! Parameter bundles for the inbound APDU dispatcher (#902).

use super::*;

/// Shared client state the dispatcher reads and notifies.
pub(super) struct DispatchContext<'a, T: TransportPort + 'static> {
    /// Transaction state machine.
    pub(super) tsm: &'a Arc<Mutex<Tsm>>,
    /// Discovered-device table.
    pub(super) device_table: &'a Arc<Mutex<DeviceTable>>,
    /// Network layer used to send replies.
    pub(super) network: &'a Arc<NetworkLayer<T>>,
    /// Broadcast channel for COV notifications.
    pub(super) cov_tx: &'a broadcast::Sender<ReceivedCOVNotification>,
    /// Broadcast channel for event notifications.
    pub(super) event_tx: &'a broadcast::Sender<ReceivedEventNotification>,
    /// How confirmed COV notifications are acknowledged.
    pub(super) confirmed_cov_ack_policy: &'a ConfirmedCOVNotificationAckPolicy,
    /// Broadcast channel for device discovery events.
    pub(super) device_tx: &'a broadcast::Sender<DeviceEvent>,
    /// Broadcast channel for device address collision events.
    pub(super) device_collision_tx: &'a broadcast::Sender<DeviceCollisionEvent>,
    /// Routes for SegmentAcks awaiting an outgoing segmented request.
    pub(super) seg_ack_senders: &'a Arc<Mutex<HashMap<SegAckKey, SegmentAckRoute>>>,
}

/// Where an inbound APDU came from and how to reply to it.
pub(super) struct InboundApdu<'a> {
    /// Immediate MAC the APDU arrived from.
    pub(super) source_mac: &'a [u8],
    /// The peer's SNET/SADR when the APDU arrived through a router.
    pub(super) source_network: &'a Option<NpduAddress>,
    /// Transport provenance snapshot for this APDU.
    pub(super) provenance: TransportProvenance,
    /// Sealed direct-response handle for an accepted direct request.
    pub(super) direct_response: Option<bacnet_transport::port::DirectResponse>,
    /// Whether the APDU was addressed to a group (broadcast or multicast).
    pub(super) is_group: bool,
    /// Channel for handing a reply to the transport, when it supplied one.
    pub(super) reply_tx: Option<oneshot::Sender<Bytes>>,
}
