//! Lifetime counters for event notifications the server did not deliver (#1142).
use super::*;
use bacnet_objects::notification_class::RecipientLookupOutcome;
use std::sync::atomic::AtomicU64;

/// Lifetime totals of event notifications that were not delivered, each
/// saturating at `u64::MAX`. A new server starts at zero, and the totals stay
/// readable after `stop()`. Fields are sampled independently, not as one
/// atomic aggregate. Each refusal also logs a warning; these totals are the
/// running signal, not an audit log.
///
/// The first four count transitions (event or acknowledgment notifications)
/// whose Notification Class lookup failed closed, so no recipient received
/// them. A class whose list is empty, or whose destinations all filter the
/// transition out by day, time or transition, is configured behaviour and is
/// not counted. Neither are notifications held back by DeviceCommunicationControl
/// or Event_Enable.
///
/// The next three count destinations that matched the transition but were
/// skipped while their route was resolved, once per destination: the rest of
/// the transition's destinations are still served. They are grouped by what
/// fixes them: a Device recipient the server holds no current address for,
/// a recipient that can never be routed as written, and a confirmed
/// recipient at a broadcast address. The warning logged with each skip names
/// the finer reason.
///
/// The last three count confirmed notifications to one recipient that were
/// never acknowledged.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct EventNotificationCounters {
    /// No Notification Class object has the class number the event object
    /// names.
    pub notification_class_missing: u64,
    /// The class exists but reading its Recipient_List failed.
    pub recipient_list_unavailable: u64,
    /// The class's Recipient_List did not decode as a whole; no decodable
    /// prefix is routed.
    pub recipient_list_invalid: u64,
    /// The class serves more than
    /// [`MAX_RECIPIENT_LIST_DESTINATIONS`](bacnet_objects::notification_class::MAX_RECIPIENT_LIST_DESTINATIONS)
    /// destinations, which only a custom Notification Class object can do.
    pub recipient_list_too_long: u64,
    /// Device recipients skipped because the server has no current binding
    /// for them: none was configured or observed, or the observed one has
    /// expired. Both clear once the device's I-Am is observed again or a
    /// binding is configured.
    pub device_recipient_unbound: u64,
    /// Recipients that cannot be routed as configured, so no binding or
    /// retry delivers them: a Device recipient whose identifier is not a
    /// Device object, or whose binding is unusable on this link, and an
    /// address that puts a MAC on the global broadcast network (65535),
    /// which names neither a broadcast nor one device.
    pub recipient_unroutable: u64,
    /// Recipients configured for confirmed notifications at a broadcast
    /// address (local, remote or global, the link's own broadcast MAC
    /// included). Clause 6.3 lets only unconfirmed requests be broadcast,
    /// and sending one unconfirmed would drop the acknowledgment the
    /// destination asks for. No invoke ID is reserved for them.
    pub confirmed_broadcast_recipient: u64,
    /// Confirmed notifications not sent because no confirmed transaction
    /// could be reserved, normally because every invoke ID was in use.
    /// Reservations refused while the server stops are not counted.
    pub confirmed_no_invoke_id: u64,
    /// Confirmed notifications the recipient answered with an Error, Reject
    /// or Abort.
    pub confirmed_rejected: u64,
    /// Confirmed notifications that drew no acknowledgment after the last
    /// retry, including attempts whose send failed locally.
    pub confirmed_unanswered: u64,
}

/// One undelivered event notification, as counted in
/// [`EventNotificationCounters`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum EventSuppression {
    NotificationClassMissing,
    RecipientListUnavailable,
    RecipientListInvalid,
    RecipientListTooLong,
    DeviceRecipientUnbound,
    RecipientUnroutable,
    ConfirmedBroadcastRecipient,
    ConfirmedNoInvokeId,
    ConfirmedRejected,
    ConfirmedUnanswered,
}

impl EventSuppression {
    /// The counter a lookup outcome moves, or `None` when the outcome
    /// delivers or is configured behaviour.
    pub(super) fn from_lookup(outcome: &RecipientLookupOutcome) -> Option<Self> {
        match outcome {
            RecipientLookupOutcome::NotificationClassMissing => {
                Some(Self::NotificationClassMissing)
            }
            RecipientLookupOutcome::RecipientListUnavailable => {
                Some(Self::RecipientListUnavailable)
            }
            RecipientLookupOutcome::RecipientListInvalid => Some(Self::RecipientListInvalid),
            RecipientLookupOutcome::RecipientListTooLong => Some(Self::RecipientListTooLong),
            RecipientLookupOutcome::NoConfiguredDestinations
            | RecipientLookupOutcome::NoMatchingDestinations
            | RecipientLookupOutcome::Matched(_) => None,
        }
    }
}

/// The server's shared storage behind [`EventNotificationCounters`].
#[derive(Debug, Default)]
pub(crate) struct EventSuppressions([AtomicU64; 10]);

impl EventSuppressions {
    pub(crate) fn record(&self, suppression: EventSuppression) {
        // Relaxed and independent, like the other server counters: no
        // ordering with the send path is promised.
        #[allow(deprecated, reason = "try_update needs Rust 1.95; the MSRV is 1.93")]
        let _ =
            self.0[suppression as usize].fetch_update(Ordering::Relaxed, Ordering::Relaxed, |n| {
                Some(n.saturating_add(1))
            });
    }

    pub(crate) fn snapshot(&self) -> EventNotificationCounters {
        let [notification_class_missing, recipient_list_unavailable, recipient_list_invalid, recipient_list_too_long, device_recipient_unbound, recipient_unroutable, confirmed_broadcast_recipient, confirmed_no_invoke_id, confirmed_rejected, confirmed_unanswered] =
            self.0.each_ref().map(|n| n.load(Ordering::Relaxed));
        EventNotificationCounters {
            notification_class_missing,
            recipient_list_unavailable,
            recipient_list_invalid,
            recipient_list_too_long,
            device_recipient_unbound,
            recipient_unroutable,
            confirmed_broadcast_recipient,
            confirmed_no_invoke_id,
            confirmed_rejected,
            confirmed_unanswered,
        }
    }
}

impl<T: TransportPort + 'static> BACnetServer<T> {
    /// Sample the lifetime totals of undelivered event notifications,
    /// including after `stop()`. See [`EventNotificationCounters`] for what
    /// each field counts and what is left out.
    pub fn event_notification_counters(&self) -> EventNotificationCounters {
        self.event_suppressions.snapshot()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const ALL: [EventSuppression; 10] = [
        EventSuppression::NotificationClassMissing,
        EventSuppression::RecipientListUnavailable,
        EventSuppression::RecipientListInvalid,
        EventSuppression::RecipientListTooLong,
        EventSuppression::DeviceRecipientUnbound,
        EventSuppression::RecipientUnroutable,
        EventSuppression::ConfirmedBroadcastRecipient,
        EventSuppression::ConfirmedNoInvokeId,
        EventSuppression::ConfirmedRejected,
        EventSuppression::ConfirmedUnanswered,
    ];

    #[test]
    fn each_suppression_moves_only_its_own_field() {
        let counters = EventSuppressions::default();
        for (step, suppression) in ALL.into_iter().enumerate() {
            for _ in 0..=step {
                counters.record(suppression);
            }
        }
        assert_eq!(
            counters.snapshot(),
            EventNotificationCounters {
                notification_class_missing: 1,
                recipient_list_unavailable: 2,
                recipient_list_invalid: 3,
                recipient_list_too_long: 4,
                device_recipient_unbound: 5,
                recipient_unroutable: 6,
                confirmed_broadcast_recipient: 7,
                confirmed_no_invoke_id: 8,
                confirmed_rejected: 9,
                confirmed_unanswered: 10,
            }
        );
    }

    #[test]
    fn counters_saturate_at_u64_max() {
        let counters = EventSuppressions::default();
        for counter in &counters.0 {
            counter.store(u64::MAX - 1, Ordering::Relaxed);
        }
        for _ in 0..3 {
            for suppression in ALL {
                counters.record(suppression);
            }
        }
        assert!(counters
            .0
            .iter()
            .all(|counter| counter.load(Ordering::Relaxed) == u64::MAX));
    }
}
