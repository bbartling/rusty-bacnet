//! The local history bound of a COV-multiple context (#986, #1039, #1163):
//! the envelope that sizes it (#1197), and eviction under it. The policy and
//! the memory ceiling it implies are in the parent module's docs.
//!
//! Eviction may take any pending change except, per reference, its newest
//! and its change in delivery: the change a part went out ahead of, sent
//! one value per notification (#1090). Parts go out in capture order, one
//! report at a time, so the change a part last went out ahead of is the only
//! one of the reference whose later values can still be waiting; each
//! reference records just that one.

use super::{
    unsigned_len, CovSubscriptionKey, DropReason, MultipleContextKey, TimedHistories, TimedHistory,
};

/// Octets of an unsegmented confirmed request's header: type and flags,
/// maximum segments and APDU, invoke ID and service choice.
const CONFIRMED_HEADER: usize = 4;
/// Octets of an unconfirmed request's header: type and service choice.
const UNCONFIRMED_HEADER: usize = 2;
/// Octets of the initiating device identifier: a context tag and the four
/// octets of the identifier, whatever the instance.
const DEVICE_IDENTIFIER: usize = 5;
/// Octets of the timestamp a notification of timestamped changes carries: an
/// application-tagged Date and Time, five octets each, between an opening and
/// a closing tag.
const TIMESTAMP: usize = 12;
/// Octets of the two tags that delimit the list of items.
const LIST_TAGS: usize = 2;

/// Octets of the APDU header before a COV-multiple notification's service
/// request, confirmed or not; a notification is never segmented.
pub(crate) fn request_header(confirmed: bool) -> usize {
    if confirmed {
        CONFIRMED_HEADER
    } else {
        UNCONFIRMED_HEADER
    }
}

/// Octets a COV-multiple notification to `context` spends outside its items,
/// counted the way the encoder lays the request out (Clauses 13.17.1 and
/// 13.18.1, and the Clause 21 production): the APDU header, then the
/// process identifier and time remaining as context-tagged unsigned values in
/// their fewest octets, the device identifier, the timestamp, and the tags
/// around the list. From 25 octets, unconfirmed with both numbers below 256,
/// to 33, confirmed with both above 2^24.
///
/// `time_remaining` is the lifetime in seconds the context had left when it
/// was admitted. Its notifications report less as time passes, which never
/// takes more octets, so the envelope never outgrows this size.
pub(crate) fn envelope_len(context: &MultipleContextKey, time_remaining: u32) -> usize {
    request_header(context.confirmed)
        + unsigned_len(u64::from(context.process_id))
        + DEVICE_IDENTIFIER
        + unsigned_len(u64::from(time_remaining))
        + TIMESTAMP
        + LIST_TAGS
}

/// Position of the oldest change of `history` that eviction may take: one
/// that is neither the reference's newest nor its change in delivery.
fn evictable(history: &TimedHistory) -> Option<usize> {
    let newest = history.entries.len().checked_sub(1)?;
    (0..newest).find(|&at| history.entries[at].seq != history.in_delivery)
}

impl TimedHistories {
    /// A part carrying some values of change `seq` of `key` went out ahead of
    /// the rest: that change is in delivery until its last value is, and the
    /// bound keeps it meanwhile (#1163).
    pub(super) fn deliver_by_value(
        &mut self,
        key: &CovSubscriptionKey,
        incarnation: u64,
        seq: u64,
    ) {
        if let Some(history) = self.incarnation_mut(key, incarnation) {
            history.in_delivery = seq;
        }
    }

    /// Evict pending changes of `key`'s context while it is over its bound:
    /// this reference's oldest evictable change first, then the oldest in the
    /// context. Stops when only changes eviction may not take are left.
    pub(super) fn enforce_bound(&mut self, key: &CovSubscriptionKey) {
        let Some(context) = key.multiple_context().cloned() else {
            return;
        };
        let Some(capacity) = self.terms.get(&context).map(|terms| terms.capacity()) else {
            return;
        };
        while self.context_bytes.get(&context).copied().unwrap_or(0) > capacity {
            let victim = match self.histories.get(key).and_then(evictable) {
                Some(at) => Some((key.clone(), at)),
                None => self
                    .histories
                    .iter()
                    .filter(|(k, _)| k.multiple_context() == Some(&context))
                    .filter_map(|(k, h)| evictable(h).map(|at| (k, at, h.entries[at].seq)))
                    .min_by_key(|&(_, _, seq)| seq)
                    .map(|(k, at, _)| (k.clone(), at)),
            };
            let Some((victim, at)) = victim else {
                return;
            };
            let evicted = self
                .histories
                .get_mut(&victim)
                .and_then(|h| h.entries.remove(at))
                .expect("victim has an evictable change");
            self.release_bytes(&victim, evicted.cost);
            self.dropped(&victim, 1, DropReason::HistoryFull);
        }
    }

    /// Return `bytes` of `key`'s pending changes to its context's bound.
    pub(super) fn release_bytes(&mut self, key: &CovSubscriptionKey, bytes: usize) {
        let Some(context) = key.multiple_context() else {
            return;
        };
        if let Some(used) = self.context_bytes.get_mut(context) {
            *used = used.saturating_sub(bytes);
            if *used == 0 {
                self.context_bytes.remove(context);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use bacnet_services::cov_multiple::{
        COVNotificationItem, COVNotificationMultipleRequest, COVNotificationValue,
    };
    use bacnet_types::enums::{ObjectType, PropertyIdentifier};
    use bacnet_types::primitives::{ObjectIdentifier, PropertyValue};
    use bytes::BytesMut;

    use super::super::tests::{
        change, context, dropped, frame, histories, key, seconds, timed_reference,
    };
    use super::super::{value_len, TimedChange, ITEM_FRAMING};
    use super::*;
    use crate::cov::{CovObservation, CovSample, CovSubscriptionTable, SubscriberEndpoint};

    /// The service request of a notification carrying `change` of Analog
    /// Value 1 alone to `context`, laid out as a report's history part.
    fn notification(
        context: &MultipleContextKey,
        time_remaining: u32,
        device: u32,
        change: &TimedChange,
    ) -> Vec<u8> {
        let frame = change.frame();
        let request = COVNotificationMultipleRequest {
            subscriber_process_identifier: context.process_id,
            initiating_device_identifier: ObjectIdentifier::new(ObjectType::DEVICE, device)
                .unwrap(),
            time_remaining,
            timestamp: Some((frame.local_date, frame.local_time)),
            list_of_cov_notifications: vec![COVNotificationItem {
                monitored_object_identifier: ObjectIdentifier::new(ObjectType::ANALOG_VALUE, 1)
                    .unwrap(),
                list_of_values: change.values().to_vec(),
            }],
        };
        let mut encoded = BytesMut::new();
        request.encode(&mut encoded).unwrap();
        encoded.to_vec()
    }

    /// A timestamped change of a REAL Present_Value of 22.5.
    fn real_present_value(second: u8) -> TimedChange {
        let sample = CovSample::new(&PropertyValue::Real(22.5)).unwrap();
        TimedChange::new(
            frame(second),
            vec![COVNotificationValue {
                property_identifier: PropertyIdentifier::PRESENT_VALUE,
                property_array_index: None,
                value: vec![0x44, 0x41, 0xB4, 0x00, 0x00],
                time_of_change: None,
            }],
            CovObservation::new(sample, None).unwrap(),
        )
    }

    /// Octets the items of a notification carrying `change` alone take.
    fn item_len(change: &TimedChange) -> usize {
        ITEM_FRAMING + change.values().iter().map(value_len).sum::<usize>()
    }

    #[test]
    fn the_envelope_is_what_the_encoder_lays_around_the_items() {
        let change = real_present_value(30);
        let widths = [0, 255, 256, 65_535, 65_536, 16_777_216, u32::MAX];
        for confirmed in [false, true] {
            for process_id in widths {
                for time_remaining in widths {
                    for device in [0, 4_194_302] {
                        let context = MultipleContextKey {
                            process_id,
                            confirmed,
                            ..context(1)
                        };
                        let wire = request_header(confirmed)
                            + notification(&context, time_remaining, device, &change).len();
                        assert_eq!(
                            wire,
                            envelope_len(&context, time_remaining) + item_len(&change),
                            "confirmed={confirmed} process={process_id} \
                             remaining={time_remaining} device={device}"
                        );
                    }
                }
            }
        }
    }

    /// #1197: at the smallest maximum APDU a subscriber can advertise, a
    /// change that one notification carries on the wire fits one
    /// notification's room in the bound too, and the bound keeps what four
    /// such notifications carry.
    #[test]
    fn at_a_50_octet_subscriber_a_change_that_fits_the_wire_fits_the_bound() {
        let (mut h, counters) = histories(8, 4);
        let k = key(1, 1);
        let small = context(1);
        h.reset(&k, 1, 0);
        h.set_sizing(&small, Some(50), 120);

        // One REAL Present_Value goes out in one 50-octet notification...
        let present_value = real_present_value(1);
        let wire = request_header(false) + notification(&small, 120, 8, &present_value).len();
        assert!(wire <= 50, "{wire} octets on the wire");
        // ...and the bound's room for one notification holds it, which the
        // largest envelope, the one every context used to be sized with,
        // does not.
        let largest = MultipleContextKey {
            process_id: u32::MAX,
            confirmed: true,
            ..context(1)
        };
        assert_eq!(envelope_len(&largest, u32::MAX), 33);
        assert!(item_len(&present_value) > 50 - 33);
        assert!(item_len(&present_value) <= h.terms[&small].notification());

        // Two changes of a two-octet value, a Binary Present_Value, each
        // one such notification: the bound keeps both.
        h.push(&k, 1, change(1, 2));
        h.push(&k, 1, change(2, 2));
        assert_eq!(seconds(&h.drain(&k, 1).1), [1, 2]);
        assert_eq!(dropped(&counters), 0);
        // A longer lifetime takes another octet in every notification, and
        // the room of four no longer holds the older change.
        h.set_sizing(&small, Some(50), 300);
        h.push(&k, 1, change(3, 2));
        h.push(&k, 1, change(4, 2));
        assert_eq!(seconds(&h.drain(&k, 1).1), [4]);
        assert_eq!(dropped(&counters), 1);
    }

    #[test]
    fn admission_sizes_the_envelope_from_the_lifetime_left() {
        let route = SubscriberEndpoint::new(&[10, 0, 0, 1, 0xBA, 0xC0], None);
        for (lifetime, envelope) in [(120, 25), (300, 26), (70_000, 27)] {
            let mut table = CovSubscriptionTable::new();
            let expires = std::time::Instant::now() + std::time::Duration::from_secs(lifetime);
            let reference = timed_reference(1, expires);
            table
                .subscribe_multiple(&context(1), &route, expires, 10, Some(50), vec![reference])
                .unwrap();
            let terms = table.timed().lock().terms[&context(1)];
            assert_eq!(
                (terms.envelope, terms.notification()),
                (envelope, 50 - envelope),
                "lifetime {lifetime}"
            );
        }
    }
}
