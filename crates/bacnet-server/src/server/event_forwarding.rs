//! Event notifications through this device's Notification Forwarder objects
//! (Clause 12.51).
//!
//! Two paths reach the forwarders. A ConfirmedEventNotification or
//! UnconfirmedEventNotification the server receives is offered to them as it
//! arrived. A notification one of this device's own objects generates is
//! offered when its Notification Class names this device's Device object as
//! a recipient, with that recipient's process identifier. Each forwarder that
//! takes the notification ([`forwarding_targets`]) sends it on to its
//! destinations, with only the process identifier changed, through the
//! server's one send path.
//!
//! A destination that names this device again hands the copy to the
//! forwarders that have not yet taken this notification, so forwarders can
//! chain within the device without a copy going round twice. Across such a
//! chain each destination (recipient, process identifier and confirmation)
//! gets one copy, however many forwarders name it.
//!
//! A received notification that no forwarder takes is still acknowledged
//! when it came confirmed; it counts in
//! [`EventNotificationCounters::received_not_forwarded`].
//!
//! One notification goes to at most [`MAX_FORWARDED_DESTINATIONS`]
//! destinations across every forwarder in such a chain; the rest are dropped
//! and counted in [`EventNotificationCounters::forwarding_cap_dropped`].
//!
//! The loop rules that need a destination's route are applied as each copy is
//! sent ([`ForwardOrigin::admits`]). The server is one node on one network, so a
//! received notification always arrives through Port_ID 0. Its network is the
//! local one, and when the registered Network Port knows that network's number
//! ([`local_network_number`]), a recipient address naming the number is local
//! to the loop rules. A copy the rules let through is sent as its recipient's
//! address is written either way.

use super::event_recipient_route::{system_utc_recipient_filter_time, RecipientRoute};
use super::event_send::OutboundNotification;
use super::event_suppression::EventSuppression;
use super::*;
use bacnet_objects::notification_class::MAX_RECIPIENT_LIST_DESTINATIONS;
use bacnet_objects::notification_forwarder::{forwarding_targets, ForwardingInput};
use bacnet_objects::subscribed_recipients::MAX_SUBSCRIBED_RECIPIENTS;
use bacnet_services::alarm_event::ForwardedEventNotification;
use bacnet_types::constructed::BACnetRecipient;

/// The Port_ID of the one network port this server receives through: a node
/// that does not route numbers its port 0 (Clause 12.51.11).
const RECEIVING_PORT: u8 = 0;

/// The most destinations one notification is forwarded to, across every
/// Notification Forwarder in this device that takes it: as many as one
/// forwarder's full Recipient_List and Subscribed_Recipients name, so no
/// single forwarder is cut short. It bounds how far one received notification
/// can multiply. Destinations naming this device's own Device object, which
/// hand the notification on within the device, do not count; the
/// destinations past the cap count in
/// [`EventNotificationCounters::forwarding_cap_dropped`].
pub const MAX_FORWARDED_DESTINATIONS: usize =
    MAX_RECIPIENT_LIST_DESTINATIONS + MAX_SUBSCRIBED_RECIPIENTS;

/// How a notification reached this device's forwarders.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum ForwardOrigin {
    /// One of this device's own objects generated it.
    Local,
    /// It arrived from the network.
    Received(Reception),
}

/// How a received notification was addressed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct Reception {
    /// Sent to a broadcast or multicast address, so every node on the
    /// receiving network already has it.
    pub(super) group: bool,
    /// Sent by global broadcast.
    pub(super) global: bool,
}

impl Reception {
    /// A notification addressed to this device alone.
    pub(super) const UNICAST: Self = Self {
        group: false,
        global: false,
    };

    /// The addressing of an unconfirmed request as the network layer saw it.
    pub(super) fn of(received: &bacnet_network::layer::ReceivedApdu) -> Self {
        Self {
            group: received.is_group,
            global: received.global_broadcast,
        }
    }
}

/// Where a route takes a copy, as the loop rules see it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Reach {
    /// Every network, by global broadcast.
    Everywhere,
    /// Every node on the local network.
    LocalBroadcast,
    /// One node on the local network.
    LocalNode,
    /// A remote network, or a node on one.
    Elsewhere,
}

impl Reach {
    /// Classify `route`, taking a network numbered `local_network` as the
    /// local network and, on it, a link broadcast MAC as a broadcast.
    fn of(
        route: &RecipientRoute,
        local_network: Option<u16>,
        is_link_broadcast: impl Fn(&[u8]) -> bool,
    ) -> Self {
        let here = |network: &u16| Some(*network) == local_network;
        match route {
            RecipientRoute::GlobalBroadcast => Self::Everywhere,
            RecipientRoute::LocalBroadcast => Self::LocalBroadcast,
            RecipientRoute::RemoteBroadcast(network) if here(network) => Self::LocalBroadcast,
            RecipientRoute::RemoteUnicast { network, mac } if here(network) => {
                if is_link_broadcast(mac) {
                    Self::LocalBroadcast
                } else {
                    Self::LocalNode
                }
            }
            RecipientRoute::BoundRoutedUnicast { network, .. } if here(network) => Self::LocalNode,
            RecipientRoute::LocalUnicast(_) | RecipientRoute::BoundLocalUnicast { .. } => {
                Self::LocalNode
            }
            _ => Self::Elsewhere,
        }
    }
}

impl ForwardOrigin {
    /// Whether a forwarded copy may go where `reach` says (Clause 12.51). No
    /// copy goes by global broadcast. A received notification is not
    /// broadcast back onto the network it arrived from, and one that arrived
    /// by broadcast goes to no node on that network, since each already has
    /// it.
    fn admits(self, reach: Reach) -> bool {
        match (self, reach) {
            (_, Reach::Everywhere) => false,
            (ForwardOrigin::Local, _) => true,
            (ForwardOrigin::Received(_), Reach::LocalBroadcast) => false,
            (ForwardOrigin::Received(reception), Reach::LocalNode) => !reception.group,
            (ForwardOrigin::Received(_), Reach::Elsewhere) => true,
        }
    }

    fn receiving_port(self) -> Option<u8> {
        match self {
            ForwardOrigin::Local => None,
            ForwardOrigin::Received(_) => Some(RECEIVING_PORT),
        }
    }
}

/// The local network's number, from the registered Network Port's
/// Network_Number, which holds a configured number or one learned from a
/// router. `None` when no port is registered or its number is unknown (zero);
/// the loop rules then take every network number as remote.
fn local_network_number(db: &ObjectDatabase) -> Option<u16> {
    let port = db.registered_bip_port_internal()?;
    match db
        .get(&port)?
        .read_property(PropertyIdentifier::NETWORK_NUMBER, None)
    {
        Ok(PropertyValue::Unsigned(number)) => u16::try_from(number)
            .ok()
            .filter(|number| (1..u16::MAX).contains(number)),
        _ => None,
    }
}

/// Split off the recipients that name `local_device`, returning their
/// distinct process identifiers.
fn take_local(
    recipients: &mut Vec<(BACnetRecipient, u32, bool)>,
    local_device: ObjectIdentifier,
) -> Vec<u32> {
    let mut local = Vec::new();
    recipients.retain(|(recipient, process_identifier, _)| {
        let is_local = *recipient == BACnetRecipient::Device(local_device);
        if is_local && !local.contains(process_identifier) {
            local.push(*process_identifier);
        }
        !is_local
    });
    local
}

impl<T: TransportPort + 'static> BACnetServer<T> {
    /// Send a notification this device generated to the recipients its
    /// Notification Class selected. Recipients naming this device's own
    /// Device object take it through the local forwarders instead of the
    /// network.
    pub(super) async fn deliver_local_notification(
        ctx: &EventDelivery<'_, T>,
        notification: EventNotificationRequest,
        recipients: &[(BACnetRecipient, u32, bool)],
    ) {
        let mut remote = recipients.to_vec();
        let local = take_local(&mut remote, notification.initiating_device_identifier);
        if !remote.is_empty() {
            let encode_for = |process_identifier| {
                let mut targeted = notification.clone();
                targeted.process_identifier = process_identifier;
                let mut buf = BytesMut::new();
                targeted.encode(&mut buf).map(|()| buf.freeze())
            };
            let outbound = OutboundNotification {
                notification_class: notification.notification_class,
                priority: notification.priority,
                encode_for: &encode_for,
                admits: &|_| true,
            };
            Self::send_event_notification(ctx, &outbound, &remote).await;
        }
        if local.is_empty() {
            return;
        }
        let forwarded = match ForwardedEventNotification::from_request(&notification) {
            Ok(forwarded) => forwarded,
            Err(error) => {
                warn!(%error, "Failed to encode EventNotification for local forwarding");
                return;
            }
        };
        for process_identifier in local {
            Self::forward_event_notification(
                ctx,
                forwarded.retargeted(process_identifier),
                ForwardOrigin::Local,
            )
            .await;
        }
    }

    /// Offer `notification` to this device's forwarders and send each copy
    /// they ask for, up to [`MAX_FORWARDED_DESTINATIONS`] destinations.
    /// Returns once every unconfirmed copy is sent and every confirmed one is
    /// handed to its notification worker; it never reports a delivery
    /// outcome to the caller.
    pub(super) async fn forward_event_notification(
        ctx: &EventDelivery<'_, T>,
        notification: ForwardedEventNotification,
        origin: ForwardOrigin,
    ) {
        if matches!(origin, ForwardOrigin::Received(reception) if reception.global) {
            debug!("Forwarders ignore an event notification sent by global broadcast");
            return;
        }
        if ctx.comm_state.load(Ordering::Acquire) >= 1 {
            return;
        }
        let mut taken = Vec::new();
        let mut sent: Vec<(BACnetRecipient, u32, bool)> = Vec::new();
        let mut pending = vec![notification];
        while let Some(notification) = pending.pop() {
            let (local_device, local_network, mut recipients) = {
                let db = ctx.db.read().await;
                let system_utc = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap_or_default();
                let (today, current_time) = match db.clock_frame() {
                    Some(frame) if frame.is_valid_actual_datetime() => (
                        frame
                            .day_of_week()
                            .expect("validated ClockFrame has a day of week"),
                        frame.local_time,
                    ),
                    _ => system_utc_recipient_filter_time(system_utc),
                };
                let input = ForwardingInput {
                    process_identifier: notification.process_identifier,
                    to_state: notification.to_state,
                    locally_initiated: origin == ForwardOrigin::Local,
                    receiving_port: origin.receiving_port(),
                    today,
                    current_time: &current_time,
                };
                let targets = forwarding_targets(&db, &input, &taken);
                if taken.is_empty()
                    && targets.forwarders.is_empty()
                    && matches!(origin, ForwardOrigin::Received(_))
                {
                    debug!(
                        process_identifier = notification.process_identifier,
                        "No Notification Forwarder takes the received event notification"
                    );
                    ctx.suppressions
                        .record(EventSuppression::ReceivedNotForwarded);
                }
                taken.extend(targets.forwarders);
                (
                    db.selected_device(),
                    local_network_number(&db),
                    targets.recipients,
                )
            };
            if let Some(local_device) = local_device {
                for process_identifier in take_local(&mut recipients, local_device) {
                    pending.push(notification.retargeted(process_identifier));
                }
            }
            recipients.retain(|destination| !sent.contains(destination));
            let room = MAX_FORWARDED_DESTINATIONS - sent.len();
            if recipients.len() > room {
                let dropped = recipients.len() - room;
                warn!(
                    dropped,
                    cap = MAX_FORWARDED_DESTINATIONS,
                    "Event notification reached the forwarding cap; dropping destinations"
                );
                for _ in 0..dropped {
                    ctx.suppressions
                        .record(EventSuppression::ForwardingCapDropped);
                }
                recipients.truncate(room);
            }
            if recipients.is_empty() {
                continue;
            }
            sent.extend(recipients.iter().cloned());
            let encode_for = |process_identifier| Ok(notification.encode_for(process_identifier));
            let network = ctx.network;
            let admits = |route: &RecipientRoute| {
                origin.admits(Reach::of(route, local_network, |mac| {
                    network.transport().is_broadcast_mac(mac)
                }))
            };
            let outbound = OutboundNotification {
                notification_class: notification.notification_class,
                priority: notification.priority,
                encode_for: &encode_for,
                admits: &admits,
            };
            Self::send_event_notification(ctx, &outbound, &recipients).await;
        }
    }
}
