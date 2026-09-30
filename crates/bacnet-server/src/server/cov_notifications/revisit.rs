//! Fan acknowledged references out again (#896).
//!
//! A confirmed report advances its baseline only on the Ack, and changes made
//! while it was outstanding were held back. Each acknowledged reference is
//! evaluated again through the usual per-subscription fanout, so it reports
//! whatever now differs from the acknowledged baseline (Status_Flags included)
//! and nothing when it is unchanged.
use super::super::cov_notify_context::{CovFanoutHandles, CovNotifyContext};
use super::*;
use crate::cov::CovSubscriptionKey;

impl<T: TransportPort + 'static> BACnetServer<T> {
    /// Evaluate the live references among `keys` against their baselines and
    /// report what changed, under one event budget. Skipped under DCC, as any
    /// fanout is.
    pub(in crate::server) async fn fire_cov_revisits(
        ctx: &CovNotifyContext<'_, T>,
        keys: &[CovSubscriptionKey],
    ) {
        if ctx.comm_state.load(Ordering::Acquire) >= 1 {
            return;
        }
        let (subs, counters, in_flight_tracker) = {
            let table = ctx.cov_table.read().await;
            (
                keys.iter()
                    .filter_map(|key| table.get_subscription(key))
                    .filter(|sub| table.is_current(sub))
                    .cloned()
                    .collect::<Vec<_>>(),
                Arc::clone(table.counters()),
                Arc::clone(table.in_flight_tracker()),
            )
        };
        if subs.is_empty() {
            return;
        }
        let handles = CovFanoutHandles {
            ctx,
            in_flight_tracker: &in_flight_tracker,
            counters: &counters,
        };
        let mut budget = EventBudget::new(&ctx.config.cov_policy);
        let mut single_by_object: HashMap<ObjectIdentifier, Vec<CovSubscriptionSnapshot>> =
            HashMap::new();
        let mut multiple = Vec::new();
        for sub in subs {
            match sub.notification_kind {
                CovNotificationKind::Single => single_by_object
                    .entry(sub.monitored_object_identifier)
                    .or_default()
                    .push(sub),
                CovNotificationKind::Multiple => multiple.push(sub),
            }
        }
        for (oid, subs) in &single_by_object {
            Self::fire_cov_notifications_for_subscriptions(
                &handles,
                oid,
                subs,
                None,
                false,
                &mut budget,
            )
            .await;
        }
        Self::fire_cov_notification_multiple_for_subscriptions(
            &handles,
            &multiple,
            None,
            false,
            &mut budget,
        )
        .await;
    }
}
