//! Splitting one COV-multiple report into notifications that each fit the
//! subscriber's maximum APDU (135-2020 §13.1, §13.18.1.1; #986).
//!
//! The report's last notification carries each timestamped reference's latest
//! change and the untimestamped values, with as much of the newest queued
//! history as still fits. The rest of the history goes out first, oldest
//! first, in as few notifications as fit. A history change that does not fit
//! a notification even alone is dropped and counted, since every attempt to
//! send it would fail. Latest changes are never split or dropped, so the last
//! notification may still exceed the limit, as an unsplit one would; that is
//! logged (#1008 tracks splitting them too).
use std::collections::HashSet;

use bacnet_services::cov_multiple::{COVNotificationItem, COVNotificationMultipleRequest};
use bacnet_types::primitives::ObjectIdentifier;
use bytes::BytesMut;
use tracing::warn;

use super::cov_clock::cov_multiple_datetime;
use super::multiple_items::{build_items, Coordinate, History, Retained, Stamp};
use crate::cov::multiple_reads::MultipleReads;
use crate::cov::timed::{value_len, TimedClaim, ITEM_FRAMING};

/// Octets of an unsegmented confirmed request header: type and flags, maximum
/// segments and APDU, invoke ID and service choice.
const CONFIRMED_HEADER: usize = 4;
/// Octets of an unconfirmed request header: type and service choice.
const UNCONFIRMED_HEADER: usize = 2;

/// Envelope fields every notification of one report shares.
pub(super) struct Envelope {
    pub(super) subscriber_process_identifier: u32,
    pub(super) initiating_device_identifier: ObjectIdentifier,
    pub(super) time_remaining: u32,
}

impl Envelope {
    fn notification(
        &self,
        timestamp: Option<bacnet_objects::clock::ClockFrame>,
        items: Vec<COVNotificationItem>,
    ) -> COVNotificationMultipleRequest {
        COVNotificationMultipleRequest {
            subscriber_process_identifier: self.subscriber_process_identifier,
            initiating_device_identifier: self.initiating_device_identifier,
            time_remaining: self.time_remaining,
            timestamp: timestamp.map(cov_multiple_datetime),
            list_of_cov_notifications: items,
        }
    }
}

/// A notification that goes out before the report's last one, with the
/// history it retires once delivered.
pub(super) struct Chunk {
    pub(super) notification: COVNotificationMultipleRequest,
    pub(super) claim: TimedClaim,
}

/// Service-request octets one notification may take: the smaller of the local
/// maximum APDU and the subscriber's, less the request header.
pub(super) fn request_limit(local: u32, subscriber: Option<u16>, confirmed: bool) -> usize {
    let local = usize::try_from(local).unwrap_or(usize::MAX);
    let apdu = subscriber.map_or(local, |subscriber| local.min(usize::from(subscriber)));
    let header = if confirmed {
        CONFIRMED_HEADER
    } else {
        UNCONFIRMED_HEADER
    };
    apdu.saturating_sub(header)
}

/// Octets the untimestamped values among `retained` take, with one item's
/// framing per object.
pub(super) fn untimed_octets(retained: &Retained<'_>) -> usize {
    let mut objects = HashSet::new();
    retained
        .iter()
        .filter(|(sub, _)| !sub.timestamped)
        .map(|(sub, values)| {
            let framing = if objects.insert(sub.monitored_object_identifier) {
                ITEM_FRAMING
            } else {
                0
            };
            framing + values.iter().map(value_len).sum::<usize>()
        })
        .sum()
}

/// What one report's notifications carry besides the claimed history.
pub(super) struct ReportContent<'a> {
    pub(super) envelope: &'a Envelope,
    pub(super) retained: &'a Retained<'a>,
    pub(super) reads: &'a MultipleReads,
    pub(super) untimed: &'a HashSet<Coordinate>,
    /// Times a field of a timestamped reference that conveys no change now,
    /// carried by a sibling (#987). Only the last notification has such
    /// current values.
    pub(super) stamp: &'a Stamp<'a>,
}

impl ReportContent<'_> {
    /// History-only notification of `history`, named after its last change.
    fn history(&self, claim: &TimedClaim, history: &History<'_>) -> COVNotificationMultipleRequest {
        let timestamp = history.last().map(|(_, change)| change.frame());
        let (items, _) = build_items(claim, history, None, self.reads, self.untimed, self.stamp);
        self.envelope.notification(timestamp, items)
    }

    /// The report's last notification: `history`, then every reference's
    /// current state. Its header names the newest change whose time it
    /// carries, claimed now or kept by a reference that conveys no change.
    fn last(&self, claim: &TimedClaim, history: &History<'_>) -> COVNotificationMultipleRequest {
        let (items, stamped) = build_items(
            claim,
            history,
            Some(self.retained),
            self.reads,
            self.untimed,
            self.stamp,
        );
        let newest = claim
            .newest()
            .into_iter()
            .chain(stamped)
            .max_by_key(|(seq, _)| *seq)
            .map(|(_, frame)| frame);
        self.envelope.notification(newest, items)
    }
}

/// Encoded length of a notification's service request; `None` if it does not
/// encode.
fn encoded_len(notification: &COVNotificationMultipleRequest) -> Option<usize> {
    let mut encoded = BytesMut::new();
    notification.encode(&mut encoded).ok()?;
    Some(encoded.len())
}

fn fits(notification: &COVNotificationMultipleRequest, limit: usize) -> bool {
    encoded_len(notification).is_some_and(|len| len <= limit)
}

/// Split the report `claim` conveys into notifications of at most `limit`
/// service-request octets. Returns the notifications that go first, oldest
/// history first, each with the claim it retires, and the last notification,
/// whose changes stay in `claim`.
pub(super) fn split(
    content: &ReportContent<'_>,
    claim: &mut TimedClaim,
    limit: usize,
) -> (Vec<Chunk>, COVNotificationMultipleRequest) {
    // Each part as its count of the oldest remaining history changes, and
    // whether that one change cannot fit a notification on its own.
    let parts = {
        let history = claim.earlier();
        let whole = content.last(claim, &history);
        // A notification that does not encode is reported by its send.
        if history.is_empty() || encoded_len(&whole).is_none_or(|len| len <= limit) {
            warn_oversized(&whole, limit);
            return (Vec::new(), whole);
        }
        // Moving more of the oldest history out never grows the rest, so the
        // fewest changes to move out can be found by bisection.
        let moved = smallest(history.len(), |count| {
            fits(&content.last(claim, &history[count..]), limit)
        });
        let mut parts = Vec::new();
        let mut start = 0;
        while start < moved {
            let alone = |end: usize| fits(&content.history(claim, &history[start..end]), limit);
            let end = largest(start + 1, moved, alone);
            parts.push((end - start, end == start + 1 && !alone(end)));
            start = end;
        }
        parts
    };
    let mut chunks = Vec::new();
    for (count, too_large) in parts {
        let part = claim.split_earliest(count);
        if too_large {
            part.discard("a timestamped change exceeds the notification size on its own");
            continue;
        }
        let notification = content.history(&part, &part.earlier());
        chunks.push(Chunk {
            notification,
            claim: part,
        });
    }
    let last = content.last(claim, &claim.earlier());
    warn_oversized(&last, limit);
    (chunks, last)
}

/// Log a last notification that still exceeds `limit`: its latest changes
/// and untimestamped values alone do not fit, and are never split (#1008).
fn warn_oversized(notification: &COVNotificationMultipleRequest, limit: usize) {
    if let Some(len) = encoded_len(notification).filter(|len| *len > limit) {
        warn!(
            octets = len,
            limit,
            "COV-multiple notification exceeds the subscriber's maximum APDU: its \
             latest changes and untimestamped values alone do not fit"
        );
    }
}

/// Smallest `count` in `1..=max` for which `fits` holds, knowing it fails at
/// zero and only flips once; `max` when it never holds.
fn smallest(max: usize, fits: impl Fn(usize) -> bool) -> usize {
    let (mut failing, mut fitting) = (0, max);
    if !fits(max) {
        return max;
    }
    while fitting - failing > 1 {
        let mid = failing + (fitting - failing) / 2;
        if fits(mid) {
            fitting = mid;
        } else {
            failing = mid;
        }
    }
    fitting
}

/// Largest `end` in `first..=max` for which `fits` holds, knowing it only
/// flips once; `first` when even that fails, so every chunk carries at least
/// one change. Gallops from `first` so the cost follows the chunk's size.
fn largest(first: usize, max: usize, fits: impl Fn(usize) -> bool) -> usize {
    if !fits(first) {
        return first;
    }
    let (mut fitting, mut step) = (first, 1);
    let mut failing = loop {
        let next = fitting + step;
        if next > max {
            break max + 1;
        }
        if !fits(next) {
            break next;
        }
        fitting = next;
        step *= 2;
    };
    while failing - fitting > 1 {
        let mid = fitting + (failing - fitting) / 2;
        if fits(mid) {
            fitting = mid;
        } else {
            failing = mid;
        }
    }
    fitting
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bisection_finds_the_flip_point() {
        for flip in 1..=9 {
            assert_eq!(smallest(9, |count| count >= flip), flip);
            assert_eq!(largest(1, 9, |end| end <= flip), flip);
        }
        assert_eq!(smallest(9, |_| false), 9, "never fits: move everything");
        assert_eq!(largest(3, 9, |_| false), 3, "at least one change");
        assert_eq!(largest(3, 9, |_| true), 9);
    }

    #[test]
    fn the_limit_is_the_smaller_maximum_less_the_header() {
        assert_eq!(request_limit(1476, None, false), 1474);
        assert_eq!(request_limit(1476, Some(206), false), 204);
        assert_eq!(request_limit(480, Some(1476), true), 476);
    }
}
