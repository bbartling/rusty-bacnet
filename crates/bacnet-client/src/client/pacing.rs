//! A minimum interval between confirmed requests to one destination (#1535).
//!
//! A slow device answers its other clients late while one client reads it
//! back to back, even with one request outstanding. With an interval set,
//! the confirmed requests to a destination take turns in call order, and
//! each goes only once the interval has passed since the request before it
//! finished, by a reply, an error or its caller giving up; while that one is
//! still outstanding, since it went. The check is made again whenever the
//! request wakes, so a reply that comes late still gets its full pause.
//! Destinations don't wait on each other, and an interval of zero changes
//! nothing.
//!
//! Pacing runs before a routed request takes its path lease. That lease is
//! shared by every device on the same network behind the same router, so
//! there a request waiting for the lease goes as soon as the lease frees: the
//! pause after a reply holds for requests made one after another, not for
//! concurrent ones.

use std::collections::HashMap;
use std::sync::{Mutex, PoisonError};

use bacnet_types::error::Error;
use bacnet_types::MacAddr;
use tokio::time::{Duration, Instant};

use super::ConfirmedTarget;

/// Most destinations the pacer remembers at once. Past it, those with
/// nothing waiting or outstanding whose interval has run out go first, then
/// the idle one free soonest, and only when every one is busy the one free
/// soonest of all.
const MAX_PACED_DESTINATIONS: usize = 4_096;

/// The longest interval a client takes: an hour.
pub const MAX_MIN_REQUEST_INTERVAL_MS: u64 = 3_600_000;

/// Refuse an interval past [`MAX_MIN_REQUEST_INTERVAL_MS`].
pub(super) fn validate_interval_ms(interval_ms: u64) -> Result<(), Error> {
    if interval_ms > MAX_MIN_REQUEST_INTERVAL_MS {
        return Err(Error::Encoding(format!(
            "invalid min-request-interval {interval_ms} ms; expected 0..={MAX_MIN_REQUEST_INTERVAL_MS}"
        )));
    }
    Ok(())
}

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

/// One request's turn at a destination.
#[derive(Debug, Clone, Copy)]
struct Turn {
    /// When it goes: the time it waits for, moved later while it waits,
    /// then the time it went.
    at: Instant,
    went: bool,
    /// When it finished; `None` while it waits or is outstanding.
    finished: Option<Instant>,
    /// The turn before it, which still binds the turn after it if this one
    /// is given up before it goes.
    follows: Option<u64>,
}

impl Turn {
    /// When the request after this one may go, as far as this one goes.
    fn free_at(&self, interval: Duration) -> Instant {
        self.finished.unwrap_or(self.at) + interval
    }

    fn abandoned(&self) -> bool {
        !self.went && self.finished.is_some()
    }
}

/// The turns at one destination still needed: the newest, and each one a
/// request still waiting follows, through any given up in between.
#[derive(Debug, Default)]
struct Lane {
    turns: HashMap<u64, Turn>,
    newest: Option<u64>,
    /// Requests waiting or outstanding.
    active: usize,
}

impl Lane {
    /// When a request following `ticket` may go: after that turn, and after
    /// each turn before it that was given up and the turn that one followed.
    fn due(&self, ticket: Option<u64>, interval: Duration) -> Option<Instant> {
        let mut due: Option<Instant> = None;
        let mut next = ticket;
        while let Some(turn) = next.and_then(|ticket| self.turns.get(&ticket)) {
            let free = turn.free_at(interval);
            due = Some(due.map_or(free, |due| due.max(free)));
            next = if turn.abandoned() { turn.follows } else { None };
        }
        due
    }

    /// Drop the turns only the request after `ticket` needed.
    fn release(&mut self, ticket: Option<u64>) {
        let mut next = ticket;
        while let Some(turn) = next.and_then(|ticket| self.turns.remove(&ticket)) {
            next = if turn.abandoned() { turn.follows } else { None };
        }
    }

    fn free_at(&self, interval: Duration, now: Instant) -> Instant {
        self.due(self.newest, interval).unwrap_or(now)
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

/// One paced request's turn, held for the life of the request; dropping it,
/// when the request finishes or its caller gives up, starts the interval for
/// the next.
#[must_use = "the request counts as finished when the guard drops"]
pub(super) struct PaceGuard<'a> {
    pacer: &'a RequestPacer,
    turn: Option<(PaceKey, u64)>,
}

impl Drop for PaceGuard<'_> {
    fn drop(&mut self) {
        let Some((key, ticket)) = self.turn.take() else {
            return;
        };
        let mut lanes = self.pacer.lock();
        let Some(lane) = lanes.by_destination.get_mut(&key) else {
            return;
        };
        lane.active = lane.active.saturating_sub(1);
        // A turn given up before it came finishes too, but stays in the
        // chain: the request after it still waits for the turns before it
        // (`Lane::due`), so it can't jump the queue.
        if let Some(turn) = lane.turns.get_mut(&ticket) {
            turn.finished = Some(Instant::now());
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

    /// Make room for one more destination.
    fn evict(&self, lanes: &mut Lanes, now: Instant) {
        let interval = self.interval;
        lanes
            .by_destination
            .retain(|_, lane| lane.active > 0 || lane.free_at(interval, now) > now);
        if lanes.by_destination.len() < self.capacity {
            return;
        }
        let soonest = |idle_only: bool| {
            lanes
                .by_destination
                .iter()
                .filter(|(_, lane)| !idle_only || lane.active == 0)
                .min_by_key(|(_, lane)| lane.free_at(interval, now))
                .map(|(key, _)| key.clone())
        };
        if let Some(key) = soonest(true).or_else(|| soonest(false)) {
            lanes.by_destination.remove(&key);
        }
    }

    /// Wait for this request's turn to `key` and return the guard the
    /// request holds until it finishes.
    ///
    /// The turn is taken under the lock, in call order, and the wait happens
    /// after it is released, so no other destination waits on it. On waking
    /// the request checks the turn before it again and waits on if that one
    /// finished later than planned. The guard exists before the wait, so a
    /// caller that gives up while waiting finishes its turn then.
    pub(super) async fn wait(&self, key: PaceKey) -> PaceGuard<'_> {
        if self.interval.is_zero() {
            return PaceGuard {
                pacer: self,
                turn: None,
            };
        }
        let interval = self.interval;
        let (ticket, previous, mut at) = {
            let mut lanes = self.lock();
            let now = Instant::now();
            if lanes.by_destination.len() >= self.capacity
                && !lanes.by_destination.contains_key(&key)
            {
                self.evict(&mut lanes, now);
            }
            lanes.next_ticket += 1;
            let ticket = lanes.next_ticket;
            let lane = lanes.by_destination.entry(key.clone()).or_default();
            let previous = lane.newest;
            let at = lane.free_at(interval, now).max(now);
            lane.turns.insert(
                ticket,
                Turn {
                    at,
                    went: false,
                    finished: None,
                    follows: previous,
                },
            );
            lane.newest = Some(ticket);
            lane.active += 1;
            (ticket, previous, at)
        };
        let guard = PaceGuard {
            pacer: self,
            turn: Some((key.clone(), ticket)),
        };
        loop {
            tokio::time::sleep_until(at).await;
            let mut lanes = self.lock();
            let now = Instant::now();
            // A destination forgotten at the cap paces nothing.
            let Some(lane) = lanes.by_destination.get_mut(&key) else {
                break;
            };
            match lane.due(previous, interval) {
                Some(due) if due > now => {
                    at = due;
                    if let Some(turn) = lane.turns.get_mut(&ticket) {
                        turn.at = due;
                    }
                }
                _ => {
                    if let Some(turn) = lane.turns.get_mut(&ticket) {
                        turn.at = now;
                        turn.went = true;
                    }
                    // Only this request followed the turns before it.
                    lane.release(previous);
                    break;
                }
            }
        }
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
