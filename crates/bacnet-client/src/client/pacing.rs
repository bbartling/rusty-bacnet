//! A minimum interval between confirmed requests to one destination (#1535).
//!
//! A slow device answers its other clients late while one client reads it
//! back to back, even with one request outstanding. With an interval set, a
//! confirmed request to a destination waits until the interval has passed
//! since the previous request to it finished, by a reply, an error or the
//! caller giving up. While that previous request is still outstanding, the
//! next waits until the interval has passed since it was sent, so concurrent
//! requests are spaced too. Destinations don't wait on each other, and an
//! interval of zero changes nothing.

use std::collections::HashMap;
use std::sync::{Mutex, PoisonError};

use bacnet_types::MacAddr;
use tokio::time::{Duration, Instant};

use super::ConfirmedTarget;

/// Most destinations the pacer remembers at once. Past it, those whose
/// interval has run out are forgotten first, since they constrain nothing;
/// if all still constrain, the one free soonest goes.
const MAX_PACED_DESTINATIONS: usize = 4_096;

/// The device a confirmed request goes to: its network, `None` for this
/// one, and its MAC.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub(super) struct PaceKey {
    network: Option<u16>,
    mac: MacAddr,
}

impl PaceKey {
    pub(super) fn of(target: ConfirmedTarget<'_>) -> Self {
        match target {
            ConfirmedTarget::Local { mac } => Self {
                network: None,
                mac: MacAddr::from_slice(mac),
            },
            ConfirmedTarget::Routed {
                dest_network,
                dest_mac,
                ..
            } => Self {
                network: Some(dest_network),
                mac: MacAddr::from_slice(dest_mac),
            },
        }
    }
}

/// The latest request to one destination.
#[derive(Debug, Clone, Copy)]
struct Lane {
    /// Which request it is, so an earlier one finishing late changes
    /// nothing.
    ticket: u64,
    /// When it was, or will be, let go.
    sent: Instant,
    /// When it finished; `None` while it is outstanding.
    finished: Option<Instant>,
}

impl Lane {
    /// When the next request to this destination may go.
    fn free_at(&self, interval: Duration) -> Instant {
        self.finished.unwrap_or(self.sent) + interval
    }
}

#[derive(Debug, Default)]
struct Lanes {
    by_destination: HashMap<PaceKey, Lane>,
    next_ticket: u64,
}

/// Spaces the confirmed requests to each destination by a fixed interval.
#[derive(Debug)]
pub(super) struct RequestPacer {
    interval: Duration,
    capacity: usize,
    lanes: Mutex<Lanes>,
}

/// Held for the life of one paced request; dropping it, when the request
/// finishes or its caller gives up, starts the interval for the next.
#[must_use = "the request counts as finished when the guard drops"]
pub(super) struct PaceGuard<'a> {
    pacer: &'a RequestPacer,
    lane: Option<(PaceKey, u64)>,
}

impl Drop for PaceGuard<'_> {
    fn drop(&mut self) {
        let Some((key, ticket)) = self.lane.take() else {
            return;
        };
        let mut lanes = self.pacer.lock();
        if let Some(lane) = lanes.by_destination.get_mut(&key) {
            if lane.ticket == ticket {
                lane.finished = Some(Instant::now());
            }
        }
    }
}

impl RequestPacer {
    pub(super) fn new(interval: Duration) -> Self {
        Self::with_capacity(interval, MAX_PACED_DESTINATIONS)
    }

    fn with_capacity(interval: Duration, capacity: usize) -> Self {
        Self {
            interval,
            capacity,
            lanes: Mutex::new(Lanes::default()),
        }
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, Lanes> {
        self.lanes.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// Wait until a request to `key` may go, and return the guard the
    /// request holds until it finishes.
    ///
    /// The slot is taken under the lock and the wait happens after it is
    /// released, so requests to one destination queue in call order without
    /// holding up any other. The guard exists before the wait, so a caller
    /// that gives up while waiting finishes its request then.
    pub(super) async fn wait(&self, key: PaceKey) -> PaceGuard<'_> {
        if self.interval.is_zero() {
            return PaceGuard {
                pacer: self,
                lane: None,
            };
        }
        let (slot, ticket) = {
            let mut lanes = self.lock();
            let now = Instant::now();
            let interval = self.interval;
            if lanes.by_destination.len() >= self.capacity
                && !lanes.by_destination.contains_key(&key)
            {
                lanes
                    .by_destination
                    .retain(|_, lane| lane.free_at(interval) > now);
                if lanes.by_destination.len() >= self.capacity {
                    let soonest = lanes
                        .by_destination
                        .iter()
                        .min_by_key(|(_, lane)| lane.free_at(interval))
                        .map(|(key, _)| key.clone());
                    if let Some(soonest) = soonest {
                        lanes.by_destination.remove(&soonest);
                    }
                }
            }
            let slot = lanes
                .by_destination
                .get(&key)
                .map_or(now, |lane| lane.free_at(interval).max(now));
            lanes.next_ticket += 1;
            let ticket = lanes.next_ticket;
            lanes.by_destination.insert(
                key.clone(),
                Lane {
                    ticket,
                    sent: slot,
                    finished: None,
                },
            );
            (slot, ticket)
        };
        let guard = PaceGuard {
            pacer: self,
            lane: Some((key, ticket)),
        };
        tokio::time::sleep_until(slot).await;
        guard
    }

    #[cfg(test)]
    pub(super) fn remembered(&self) -> usize {
        self.lock().by_destination.len()
    }

    #[cfg(test)]
    pub(super) fn remembers(&self, key: &PaceKey) -> bool {
        self.lock().by_destination.contains_key(key)
    }
}

#[cfg(test)]
pub(super) fn with_capacity(interval: Duration, capacity: usize) -> RequestPacer {
    RequestPacer::with_capacity(interval, capacity)
}
