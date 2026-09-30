//! Admission and delivery of one confirmed COV notification, ordinary or
//! Multiple. Its references' baselines advance only on the subscriber's Ack
//! (#896); see `crate::cov::confirmed` for the outstanding-report policy.
use super::super::cov_notify_context::CovFanoutHandles;
use super::*;
use crate::cov::timed::TimedClaim;
use crate::cov::{CovObservation, CovSubscriptionKey, PreparedCovCompletion};

/// A confirmed notification ready for admission.
pub(in crate::server) struct ConfirmedReport {
    pub(in crate::server) service: ConfirmedServiceChoice,
    /// Reference whose recipient and current route receive the notification.
    pub(in crate::server) route: CovSubscriptionSnapshot,
    /// Each carried reference with the observation its Ack completes.
    pub(in crate::server) completions: Vec<(
        CovSubscriptionSnapshot,
        CovObservation,
        PreparedCovCompletion,
    )>,
    /// Timestamped history conveyed; it retires on the Ack and otherwise
    /// returns to its references.
    pub(in crate::server) claim: Option<TimedClaim>,
}

impl ConfirmedReport {
    fn label(&self) -> &'static str {
        if self.service == ConfirmedServiceChoice::CONFIRMED_COV_NOTIFICATION {
            "COV notification"
        } else {
            "COVNotificationMultiple"
        }
    }

    fn keys(&self) -> impl Iterator<Item = CovSubscriptionKey> + '_ {
        self.completions.iter().map(|(sub, _, _)| sub.key().clone())
    }
}

impl<T: TransportPort + 'static> BACnetServer<T> {
    /// Admit `report` against the peer and global in-flight limits, an invoke
    /// ID, the event budget and its references' outstanding-report marks, then
    /// deliver it with the usual retries. `encode` builds the APDU for the
    /// reserved invoke ID.
    pub(in crate::server) async fn send_confirmed_cov(
        handles: &CovFanoutHandles<'_, '_, T>,
        budget: &mut EventBudget,
        report: ConfirmedReport,
        encode: impl FnOnce(u8) -> Result<BytesMut, Error>,
    ) {
        let &CovFanoutHandles {
            ctx,
            in_flight_tracker,
            counters,
        } = handles;
        let label = report.label();
        let guard = match in_flight_tracker.try_acquire(
            report.route.recipient(),
            ctx.config.cov_policy.max_confirmed_in_flight_per_peer,
            ctx.cov_in_flight,
        ) {
            Ok(guard) => guard,
            Err(InFlightAcquireError::PeerLimitExceeded) => {
                counters
                    .notifications_throttled_peer
                    .fetch_add(1, Ordering::Relaxed);
                return;
            }
            Err(InFlightAcquireError::GlobalPoolExhausted) => {
                warn!(
                    object = ?report.route.monitored_object_identifier,
                    "255 confirmed COV notifications in-flight, skipping {label}"
                );
                return;
            }
        };
        let (operation, result_rx) = match ctx
            .notification_transactions
            .reserve(Self::canonical_cov_peer(&report.route), report.service)
        {
            Ok(reservation) => reservation,
            Err(error) => {
                warn!(%error, "No free invoke ID for confirmed {label}");
                return;
            }
        };
        let buf = match encode(operation.invoke_id()) {
            Ok(buf) => buf,
            Err(error) => {
                warn!(%error, "Failed to encode confirmed {label}");
                return;
            }
        };
        if !budget.try_consume(buf.len()) {
            counters
                .notifications_throttled_fanout
                .fetch_add(1, Ordering::Relaxed);
            return;
        }
        let (flight, revisits) = {
            let mut table = ctx.cov_table.write().await;
            let flight = table.begin_confirmed(
                report
                    .completions
                    .iter()
                    .map(|(sub, _, completion)| (sub, *completion)),
            );
            if flight.is_none() {
                // A concurrent report or acknowledgment of one of these
                // references won the race; evaluate them all again against
                // what it left behind.
                table.revisits().request(report.keys());
            }
            (flight, Arc::clone(table.revisits()))
        };
        let Some(flight) = flight else {
            budget.refund(buf.len());
            return;
        };

        counters.notifications_sent.fetch_add(1, Ordering::Relaxed);
        counters
            .notifications_confirmed
            .fetch_add(1, Ordering::Relaxed);
        counters
            .notification_bytes_sent
            .fetch_add(buf.len() as u64, Ordering::Relaxed);

        let id = operation.invoke_id();
        let network = Arc::clone(ctx.network);
        let cov_table = Arc::clone(ctx.cov_table);
        let apdu_timeout = Duration::from_millis(ctx.config.cov_retry_timeout_ms);
        let apdu_retries = DEFAULT_APDU_RETRIES;
        ctx.notification_transactions.spawn(async move {
            let ConfirmedReport {
                route,
                completions,
                claim,
                ..
            } = report;
            let result = run_notification_worker(
                operation,
                result_rx,
                apdu_timeout,
                apdu_retries,
                |attempt| {
                    let network = Arc::clone(&network);
                    let buf = buf.clone();
                    let route = route.clone();
                    async move {
                        let result = Self::send_cov_apdu(&network, &buf, &route, true).await;
                        match &result {
                            Ok(()) => debug!(invoke_id = id, attempt, "Confirmed {label} sent"),
                            Err(error) => warn!(%error, attempt, "{label} send failed"),
                        }
                        result
                    }
                },
            )
            .await;
            match result {
                NotificationWorkerResult::Ack => debug!(invoke_id = id, "{label} acknowledged"),
                NotificationWorkerResult::Error => {
                    warn!(invoke_id = id, "{label} rejected by subscriber");
                }
                NotificationWorkerResult::Exhausted => warn!(
                    invoke_id = id,
                    "{label} failed after {} retries", apdu_retries
                ),
                NotificationWorkerResult::Closed => {}
            }
            let acknowledged = if result == NotificationWorkerResult::Ack {
                let mut table = cov_table.write().await;
                if let Some(claim) = claim {
                    claim.commit();
                }
                completions
                    .into_iter()
                    .filter(|(sub, observation, completion)| {
                        table.complete_observation(sub, *completion, observation.clone())
                    })
                    .map(|(sub, _, _)| sub.key().clone())
                    .collect()
            } else {
                // Return unacknowledged history before any mark clears, so a
                // later report conveys it again in capture order.
                drop(claim);
                Vec::new()
            };
            // Free the peer slot and marks before the follow-up needs them.
            drop(flight);
            drop(guard);
            revisits.request(acknowledged);
        });
    }
}
