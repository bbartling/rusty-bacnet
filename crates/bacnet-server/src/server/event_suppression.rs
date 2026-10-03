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
pub(crate) struct EventSuppressions([AtomicU64; 7]);

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
        let [notification_class_missing, recipient_list_unavailable, recipient_list_invalid, recipient_list_too_long, confirmed_no_invoke_id, confirmed_rejected, confirmed_unanswered] =
            self.0.each_ref().map(|n| n.load(Ordering::Relaxed));
        EventNotificationCounters {
            notification_class_missing,
            recipient_list_unavailable,
            recipient_list_invalid,
            recipient_list_too_long,
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

    const ALL: [EventSuppression; 7] = [
        EventSuppression::NotificationClassMissing,
        EventSuppression::RecipientListUnavailable,
        EventSuppression::RecipientListInvalid,
        EventSuppression::RecipientListTooLong,
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
                confirmed_no_invoke_id: 5,
                confirmed_rejected: 6,
                confirmed_unanswered: 7,
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
