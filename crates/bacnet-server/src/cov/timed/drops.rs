//! Dropped timestamped COV-multiple changes: every one is counted, and the log
//! gets one warning per context for each cause (#1039).
//!
//! A subscriber whose maximum APDU cannot hold one timestamped change of its
//! references loses every such change, and a context blocked for long keeps
//! evicting from its history bound. A warning per drop would flood the log
//! in both cases, so after a context's first warning for a cause, later drops
//! for that cause are only counted (and logged at debug level). The context
//! warns again once it is admitted afresh: a timestamped reference of it is
//! (re)published, or an admission changes the size of its notifications.

use std::sync::atomic::Ordering;

use tracing::{debug, warn};

use super::{CovSubscriptionKey, TimedHistories};

/// Why pending timestamped changes were dropped.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum DropReason {
    /// Evicted on overflow of the context's history bound.
    HistoryFull,
    /// Too large for any notification to the subscriber, even on its own.
    TooLarge,
    /// Superseded by a newer change of the reference that was delivered.
    Superseded,
}

impl DropReason {
    fn describe(self) -> &'static str {
        match self {
            Self::HistoryFull => "context history full",
            Self::TooLarge => {
                "a timestamped change exceeds every notification to the subscriber on its own"
            }
            Self::Superseded => "superseded by a delivered newer change",
        }
    }

    fn bit(self) -> u8 {
        1 << self as u8
    }
}

/// Causes a context has warned about since it was last admitted afresh.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub(super) struct DropWarnings(u8);

impl DropWarnings {
    /// Note a drop for `reason`; `true` if it is the first since the reset.
    fn first(&mut self, reason: DropReason) -> bool {
        let first = self.0 & reason.bit() == 0;
        self.0 |= reason.bit();
        first
    }
}

impl TimedHistories {
    /// Count `count` dropped changes of `key`, and warn unless its context
    /// already did for `reason`. A reference whose context has no terms left
    /// (it lost its last timestamped reference meanwhile) always warns.
    pub(super) fn dropped(&mut self, key: &CovSubscriptionKey, count: usize, reason: DropReason) {
        self.counters
            .timed_changes_dropped
            .fetch_add(count as u64, Ordering::Relaxed);
        let context = key.multiple_context();
        let terms = context.and_then(|context| self.terms.get_mut(context));
        let apdu = terms.as_ref().map(|terms| terms.apdu);
        if terms.is_none_or(|terms| terms.warned.first(reason)) {
            warn!(
                object = ?key.object(),
                recipient = ?context.map(|context| &context.recipient),
                process = context.map(|context| context.process_id),
                apdu,
                count,
                reason = reason.describe(),
                "Dropped pending timestamped COV-multiple changes; further drops in this \
                 context for the same reason are only counted in timed_changes_dropped"
            );
        } else {
            debug!(
                object = ?key.object(),
                count,
                reason = reason.describe(),
                "Dropped pending timestamped COV-multiple changes"
            );
        }
    }
}

/// Test hook: counts the drop warnings this module logs on the thread it is
/// installed on, debug-level drops excluded.
#[cfg(test)]
#[derive(Clone, Default)]
pub(crate) struct DropWarningCount(std::sync::Arc<std::sync::atomic::AtomicUsize>);

#[cfg(test)]
impl DropWarningCount {
    /// Count on this thread until the returned guard drops. Under a
    /// current-thread runtime that covers the server's tasks too.
    pub(crate) fn install(&self) -> tracing::subscriber::DefaultGuard {
        // As in the DCC trace tests: keep a second, disabled dispatcher alive
        // so a callsite another test registered first, with no subscriber of
        // its own, is not cached as never enabled.
        static REGISTRATION_PEER: std::sync::OnceLock<tracing::Dispatch> =
            std::sync::OnceLock::new();
        REGISTRATION_PEER
            .get_or_init(|| tracing::Dispatch::new(tracing::subscriber::NoSubscriber::default()));
        tracing::subscriber::set_default(self.clone())
    }

    /// Drop warnings counted so far.
    pub(crate) fn get(&self) -> usize {
        self.0.load(Ordering::SeqCst)
    }
}

#[cfg(test)]
impl tracing::Subscriber for DropWarningCount {
    fn register_callsite(
        &self,
        _: &'static tracing::Metadata<'static>,
    ) -> tracing::subscriber::Interest {
        tracing::subscriber::Interest::sometimes()
    }
    fn max_level_hint(&self) -> Option<tracing::metadata::LevelFilter> {
        Some(tracing::metadata::LevelFilter::WARN)
    }
    fn enabled(&self, metadata: &tracing::Metadata<'_>) -> bool {
        metadata.target() == module_path!() && *metadata.level() == tracing::Level::WARN
    }
    fn new_span(&self, _: &tracing::span::Attributes<'_>) -> tracing::span::Id {
        tracing::span::Id::from_u64(1)
    }
    fn record(&self, _: &tracing::span::Id, _: &tracing::span::Record<'_>) {}
    fn record_follows_from(&self, _: &tracing::span::Id, _: &tracing::span::Id) {}
    fn event(&self, event: &tracing::Event<'_>) {
        if self.enabled(event.metadata()) {
            self.0.fetch_add(1, Ordering::SeqCst);
        }
    }
    fn enter(&self, _: &tracing::span::Id) {}
    fn exit(&self, _: &tracing::span::Id) {}
}

#[cfg(test)]
mod tests {
    use super::super::tests::{histories, key};
    use super::*;

    #[test]
    fn each_cause_warns_once_per_context_until_it_is_admitted_afresh() {
        let warnings = DropWarningCount::default();
        let _guard = warnings.install();
        let (mut h, counters) = histories(8, 4);
        let (a, b, other) = (key(1, 1), key(1, 2), key(2, 1));
        for k in [&a, &b, &other] {
            h.reset(k, 1, 10);
        }
        let context = a.multiple_context().unwrap().clone();
        h.set_apdu(&context, Some(50));
        let dropped = || counters.timed_changes_dropped.load(Ordering::Relaxed);
        // Several drops of one cause, across the context's references, warn
        // once; every change is counted.
        h.dropped(&a, 1, DropReason::TooLarge);
        h.dropped(&b, 2, DropReason::TooLarge);
        h.dropped(&a, 1, DropReason::TooLarge);
        assert_eq!((warnings.get(), dropped()), (1, 4));
        // Another cause, or another context, warns for itself.
        h.dropped(&a, 1, DropReason::HistoryFull);
        h.dropped(&other, 1, DropReason::TooLarge);
        assert_eq!((warnings.get(), dropped()), (3, 6));
        // A renewal advertising the same maximum APDU changes nothing...
        h.set_apdu(&context, Some(50));
        h.dropped(&a, 1, DropReason::TooLarge);
        assert_eq!(warnings.get(), 3);
        // ...while one advertising another size warns afresh,
        h.set_apdu(&context, Some(128));
        h.dropped(&a, 1, DropReason::TooLarge);
        assert_eq!(warnings.get(), 4);
        // and so does a re-admitted reference of the context.
        h.dropped(&b, 1, DropReason::TooLarge);
        assert_eq!(warnings.get(), 4);
        h.reset(&b, 2, 10);
        h.dropped(&a, 1, DropReason::TooLarge);
        assert_eq!((warnings.get(), dropped()), (5, 10));
        // A reference whose context has no terms left always warns.
        h.remove(&other);
        h.dropped(&other, 1, DropReason::Superseded);
        h.dropped(&other, 1, DropReason::Superseded);
        assert_eq!((warnings.get(), dropped()), (7, 12));
    }
}
