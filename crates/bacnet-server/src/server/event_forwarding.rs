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
//! chain within the device without a copy going round twice.
//!
//! The loop rules that need a destination's route are applied as each copy is
//! sent ([`ForwardOrigin::admits`]). The server is one node on one network, so a
//! received notification always arrives through Port_ID 0.

use super::event_recipient_route::{system_utc_recipient_filter_time, RecipientRoute};
use super::event_send::OutboundNotification;
use super::*;
use bacnet_objects::notification_forwarder::{forwarding_targets, ForwardingInput};
use bacnet_services::alarm_event::ForwardedEventNotification;
use bacnet_types::constructed::BACnetRecipient;

/// The Port_ID of the one network port this server receives through: a node
/// that does not route numbers its port 0 (Clause 12.51.11).
const RECEIVING_PORT: u8 = 0;

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

impl ForwardOrigin {
    /// Whether a forwarded copy may take `route` (Clause 12.51). No copy goes
    /// by global broadcast. A received notification is not broadcast back
    /// onto the network it arrived from, and one that arrived by broadcast
    /// goes to no node on that network, since each already has it.
    fn admits(self, route: &RecipientRoute) -> bool {
        let resident = matches!(
            route,
            RecipientRoute::LocalUnicast(_) | RecipientRoute::BoundLocalUnicast { .. }
        );
        match (self, route) {
            (_, RecipientRoute::GlobalBroadcast) => false,
            (ForwardOrigin::Local, _) => true,
            (ForwardOrigin::Received(_), RecipientRoute::LocalBroadcast) => false,
            (ForwardOrigin::Received(reception), _) => !(reception.group && resident),
        }
    }

    fn receiving_port(self) -> Option<u8> {
        match self {
            ForwardOrigin::Local => None,
            ForwardOrigin::Received(_) => Some(RECEIVING_PORT),
        }
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
    /// they ask for. Returns once every unconfirmed copy is sent and every
    /// confirmed one is handed to its notification worker; it never reports
    /// a delivery outcome to the caller.
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
        let mut pending = vec![notification];
        while let Some(notification) = pending.pop() {
            let (local_device, mut recipients) = {
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
                taken.extend(targets.forwarders);
                (
                    crate::local_device::selected_device(&db),
                    targets.recipients,
                )
            };
            if let Some(local_device) = local_device {
                for process_identifier in take_local(&mut recipients, local_device) {
                    pending.push(notification.retargeted(process_identifier));
                }
            }
            if recipients.is_empty() {
                continue;
            }
            let encode_for = |process_identifier| Ok(notification.encode_for(process_identifier));
            let admits = |route: &RecipientRoute| origin.admits(route);
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
