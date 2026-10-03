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
//! destinations across every forwarder in such a chain, counting only the
//! copies the loop and route rules let through ([`ForwardingBudget`]); the
//! rest are dropped and counted in
//! [`EventNotificationCounters::forwarding_cap_dropped`]. A local
//! notification that names this device's Device object under several
//! process identifiers is one notification, with one cap.
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
use bacnet_encoding::constructed::encode_event_notification;
use bacnet_objects::notification_class::MAX_RECIPIENT_LIST_DESTINATIONS;
use bacnet_objects::notification_forwarder::{forwarding_targets, ForwardingInput};
use bacnet_objects::subscribed_recipients::MAX_SUBSCRIBED_RECIPIENTS;
use bacnet_services::alarm_event::ForwardedEventNotification;
use bacnet_types::constructed::BACnetRecipient;
use std::sync::atomic::AtomicUsize;

/// The Port_ID of the one network port this server receives through: a node
/// that does not route numbers its port 0 (Clause 12.51.11).
const RECEIVING_PORT: u8 = 0;

/// The most destinations one notification is forwarded to, across every
/// Notification Forwarder in this device that takes it: as many as one
/// forwarder's full Recipient_List and Subscribed_Recipients name, so no
/// single forwarder is cut short. It bounds how far one received notification
/// can multiply. Only copies that would be sent count: a destination the
/// loop rules refuse, whose route is skipped, or whose copy is too large is
/// not. Destinations naming this device's own Device object, which hand the
/// notification on within the device, do not count either. The destinations
/// past the cap count in [`EventNotificationCounters::forwarding_cap_dropped`].
pub const MAX_FORWARDED_DESTINATIONS: usize =
    MAX_RECIPIENT_LIST_DESTINATIONS + MAX_SUBSCRIBED_RECIPIENTS;

/// How often a capped notification is logged at warn level, process-wide;
/// the ones in between log at debug and still count.
pub(super) const CAP_WARNING_INTERVAL: Duration = Duration::from_secs(60);

/// The process-wide throttle on the forwarding-cap warning.
static CAP_WARNINGS: WarnThrottle = WarnThrottle::new();

/// Lets a warning through once per [`CAP_WARNING_INTERVAL`].
pub(super) struct WarnThrottle(std::sync::Mutex<Option<Instant>>);

impl WarnThrottle {
    pub(super) const fn new() -> Self {
        Self(std::sync::Mutex::new(None))
    }

    /// Whether a warning at `now` goes out: the first one does, and then one
    /// whenever the interval has passed since the last that did.
    pub(super) fn due(&self, now: Instant) -> bool {
        let mut last = self
            .0
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        match *last {
            Some(at) if now.saturating_duration_since(at) < CAP_WARNING_INTERVAL => false,
            _ => {
                *last = Some(now);
                true
            }
        }
    }
}

/// What is left of one notification's [`MAX_FORWARDED_DESTINATIONS`],
/// shared by every copy it makes. The send path takes room for a copy only
/// once the copy passed every rule and is about to go out.
pub(super) struct ForwardingBudget {
    remaining: AtomicUsize,
    dropped: AtomicUsize,
}

impl ForwardingBudget {
    fn new() -> Self {
        Self {
            remaining: AtomicUsize::new(MAX_FORWARDED_DESTINATIONS),
            dropped: AtomicUsize::new(0),
        }
    }

    /// Take room for one more copy, or, when none is left, note it as
    /// dropped and return `false`. Copies of one notification are sent one
    /// after another, so relaxed ordering is enough.
    pub(super) fn take(&self) -> bool {
        #[allow(deprecated, reason = "try_update needs Rust 1.95; the MSRV is 1.93")]
        let taken = self
            .remaining
            .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |n| n.checked_sub(1))
            .is_ok();
        if !taken {
            self.dropped.fetch_add(1, Ordering::Relaxed);
        }
        taken
    }

    fn dropped(&self) -> usize {
        self.dropped.load(Ordering::Relaxed)
    }
}

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
                encode_event_notification(&targeted, &mut buf).map(|()| buf.freeze())
            };
            let outbound = OutboundNotification {
                notification_class: notification.notification_class,
                priority: notification.priority,
                encode_for: &encode_for,
                admits: &|_| true,
                budget: None,
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
        // One notification, whatever number of process identifiers names
        // this device: one cap, and one copy per destination.
        let offered = local
            .into_iter()
            .map(|process_identifier| forwarded.retargeted(process_identifier))
            .collect();
        Self::forward_event_notification(ctx, offered, ForwardOrigin::Local).await;
    }

    /// Offer one notification, as `offered` gives it to this device's
    /// forwarders (one entry per process identifier it reaches them under),
    /// and send each copy they ask for, up to [`MAX_FORWARDED_DESTINATIONS`]
    /// destinations in all. Returns once every unconfirmed copy is sent and
    /// every confirmed one is handed to its notification worker; it never
    /// reports a delivery outcome to the caller.
    pub(super) async fn forward_event_notification(
        ctx: &EventDelivery<'_, T>,
        offered: Vec<ForwardedEventNotification>,
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
        let budget = ForwardingBudget::new();
        // A stack, so each entry's hand-offs within the device run before the
        // next entry; reversed so the entries run in the order given.
        let mut pending = offered;
        pending.reverse();
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
                budget: Some(&budget),
            };
            Self::send_event_notification(ctx, &outbound, &recipients).await;
        }
        let dropped = budget.dropped();
        if dropped > 0 {
            if CAP_WARNINGS.due(Instant::now()) {
                warn!(
                    dropped,
                    cap = MAX_FORWARDED_DESTINATIONS,
                    "Event notification reached the forwarding cap; destinations dropped \
                     (further cap drops log at debug for a minute)"
                );
            } else {
                debug!(
                    dropped,
                    cap = MAX_FORWARDED_DESTINATIONS,
                    "Event notification reached the forwarding cap; destinations dropped"
                );
            }
        }
    }
}
