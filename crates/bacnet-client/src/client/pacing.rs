//! A minimum interval between confirmed requests to one destination (#1535).
//!
//! A slow device answers its other clients late while one client reads it
//! back to back, even with one request outstanding. With an interval set,
//! each confirmed request to a destination waits until the interval has
//! passed since the previous one to it was let go. Destinations don't wait
//! on each other, and an interval of zero changes nothing.

use std::collections::HashMap;
use std::sync::{Mutex, PoisonError};

use bacnet_types::MacAddr;
use tokio::time::{Duration, Instant};

use super::ConfirmedTarget;

/// Most destinations the pacer remembers at once. Past it, those idle for a
/// whole interval are forgotten first, since they constrain nothing; if all
/// are still busy, the one free soonest goes.
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

/// Spaces the confirmed requests to each destination by a fixed interval.
#[derive(Debug)]
pub(super) struct RequestPacer {
    interval: Duration,
    /// When the latest request to each destination was, or will be, let go.
    slots: Mutex<HashMap<PaceKey, Instant>>,
}

impl RequestPacer {
    pub(super) fn new(interval: Duration) -> Self {
        Self {
            interval,
            slots: Mutex::new(HashMap::new()),
        }
    }

    /// Wait until a request to `key` may go.
    ///
    /// The slot is taken under the lock and the wait happens after it is
    /// released, so requests to one destination queue in call order without
    /// holding up any other. A caller that gives up while waiting keeps its
    /// slot, so the next request still waits out the interval after it.
    pub(super) async fn wait(&self, key: PaceKey) {
        if self.interval.is_zero() {
            return;
        }
        let slot = {
            let mut slots = self.slots.lock().unwrap_or_else(PoisonError::into_inner);
            let now = Instant::now();
            if slots.len() >= MAX_PACED_DESTINATIONS && !slots.contains_key(&key) {
                let interval = self.interval;
                slots.retain(|_, last| *last + interval > now);
                if slots.len() >= MAX_PACED_DESTINATIONS {
                    let soonest = slots
                        .iter()
                        .min_by_key(|(_, last)| **last)
                        .map(|(key, _)| key.clone());
                    if let Some(soonest) = soonest {
                        slots.remove(&soonest);
                    }
                }
            }
            let slot = slots
                .get(&key)
                .map_or(now, |last| (*last + self.interval).max(now));
            slots.insert(key, slot);
            slot
        };
        tokio::time::sleep_until(slot).await;
    }

    #[cfg(test)]
    pub(super) fn remembered(&self) -> usize {
        self.slots
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .len()
    }
}
