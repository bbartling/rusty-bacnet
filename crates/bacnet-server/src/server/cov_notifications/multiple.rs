use super::super::cov_notify_context::{CovFanoutHandles, CovNotifyContext};
use super::confirmed::ConfirmedReport;
use super::cov_clock::cov_multiple_datetime;
use super::multiple_items::build_items;
use super::*;
use crate::cov::multiple_reads::MultipleReads;
use crate::cov::timed::{TimedChange, TimedClaim};

/// Octets of an unsegmented confirmed-request APDU header.
const CONFIRMED_REQUEST_HEADER: usize = 4;
use std::collections::HashSet;

impl<T: TransportPort + 'static> BACnetServer<T> {
    /// Fire the initial COVNotificationMultiple for a newly accepted
    /// SubscribeCOVPropertyMultiple request.
    pub(in crate::server) async fn fire_initial_cov_notification_multiple(
        ctx: &CovNotifyContext<'_, T>,
        subscriptions: &[CovSubscriptionSnapshot],
    ) {
        let (counters, in_flight_tracker, subscriptions) = {
            let table = ctx.cov_table.read().await;
            (
                Arc::clone(table.counters()),
                Arc::clone(table.in_flight_tracker()),
                subscriptions
                    .iter()
                    .filter(|sub| table.is_current(sub))
                    .cloned()
                    .collect::<Vec<_>>(),
            )
        };
        let mut budget = EventBudget::new(&ctx.config.cov_policy);
        Self::fire_cov_notification_multiple_for_subscriptions(
            &CovFanoutHandles {
                ctx,
                in_flight_tracker: &in_flight_tracker,
                counters: &counters,
            },
            &subscriptions,
            None,
            true,
            &mut budget,
        )
        .await;
    }

    pub(in crate::server) async fn fire_cov_notification_multiple_for_subscriptions(
        handles: &CovFanoutHandles<'_, '_, T>,
        subscriptions: &[CovSubscriptionSnapshot],
        snapshot: Option<&dyn bacnet_objects::traits::BACnetObject>,
        force: bool,
        budget: &mut EventBudget,
    ) {
        if handles.ctx.comm_state.load(Ordering::Acquire) >= 1 || subscriptions.is_empty() {
            return;
        }

        if budget.is_exhausted() {
            return;
        }

        let mut grouped: HashMap<crate::cov::MultipleContextKey, Vec<CovSubscriptionSnapshot>> =
            HashMap::new();

        for sub in subscriptions {
            grouped
                .entry(
                    sub.key()
                        .multiple_context()
                        .expect("Multiple snapshot")
                        .clone(),
                )
                .or_default()
                .push(sub.clone());
        }

        for subs in grouped.values() {
            Self::send_cov_notification_multiple(handles, subs, snapshot, force, budget).await;
        }
    }

    async fn send_cov_notification_multiple(
        handles: &CovFanoutHandles<'_, '_, T>,
        subscriptions: &[CovSubscriptionSnapshot],
        snapshot: Option<&dyn bacnet_objects::traits::BACnetObject>,
        force: bool,
        budget: &mut EventBudget,
    ) {
        let &CovFanoutHandles {
            ctx:
                &CovNotifyContext {
                    db,
                    network,
                    cov_table,
                    config,
                    ..
                },
            counters,
            ..
        } = handles;
        if subscriptions.is_empty() {
            return;
        }

        // Timestamped changes drained for this notification; dropping the claim
        // without commit (any early return, failed send) requeues them.
        let mut claim: Option<TimedClaim> = None;
        let (notification, last_notified, representative) = {
            // One DB borrow, released before any send, supplies the Device
            // identity, the clock sample for any current-state fallback and
            // every value. A producer snapshot carries its own captured
            // changes, so that path takes no fallback clock.
            let (device_oid, clock_frame, db) = if snapshot.is_none() {
                let db = db.read().await;
                let clock_frame = subscriptions
                    .iter()
                    .any(|sub| sub.timestamped)
                    .then(|| db.clock_frame())
                    .flatten()
                    .filter(|frame| frame.is_valid_actual_datetime());
                (
                    crate::local_device::selected_device(&db),
                    clock_frame,
                    Some(db),
                )
            } else {
                (
                    crate::local_device::selected_device(&*db.read().await),
                    None,
                    None,
                )
            };
            let device_oid =
                device_oid.unwrap_or_else(|| ObjectIdentifier::new(ObjectType::DEVICE, 0).unwrap());
            let object_of = |sub: &CovSubscriptionSnapshot| {
                snapshot
                    .filter(|object| object.object_identifier() == sub.monitored_object_identifier)
                    .or_else(|| db.as_deref()?.get(&sub.monitored_object_identifier))
            };
            // One read per object in this context; all selected values and
            // companions share this DB/snapshot borrow, never a cross-context cache.
            let mut reads = MultipleReads::default();
            for sub in subscriptions {
                if let Some(object) = object_of(sub) {
                    reads.capture_source(object, sub);
                }
            }
            // Untimestamped references qualify now; timestamped ones are decided
            // under the table guard below, against their captured history.
            let mut candidates = Vec::new();
            for sub in subscriptions {
                let Some(object) = object_of(sub) else {
                    continue;
                };
                if sub.timestamped {
                    // A producer snapshot's changes were captured at the
                    // producer; only a database preparation adds current state.
                    let current = snapshot
                        .is_none()
                        .then(|| reads.read(object, sub))
                        .flatten();
                    candidates.push((sub, Err(current)));
                    continue;
                }
                let Some(prepared) =
                    reads.prepare(object, sub, sub.last_notified_observation.as_ref(), force)
                else {
                    continue;
                };
                let Some(completion) = sub.prepare_completion() else {
                    continue;
                };
                candidates.push((sub, Ok((prepared.values, prepared.observation, completion))));
            }

            // Established lock order: DB read -> table read -> timed store. No
            // object callback runs under the table guard. Each prepared value
            // owns its own check; a live sibling with a failed read cannot
            // authorize a stale value.
            let context = subscriptions[0]
                .key()
                .multiple_context()
                .expect("Multiple snapshot")
                .clone();
            let (retained, untimed) = {
                let table = cov_table.read().await;
                // A confirmed context has at most one outstanding report, and
                // the next one has to batch everything held meanwhile (#896).
                // That report's Ack, or the first fanout after a hold-off, sends
                // it; nothing is drained until then.
                if !table.context_idle(&context, subscriptions) {
                    return;
                }
                // A failed report's changes can sit on any object of the
                // context. The first fanout after its hold-off hands the whole
                // context to one follow-up instead of reporting only its own
                // object.
                if table.take_owed_context(&context) {
                    table.revisits().request(
                        table
                            .multiple_context_references(&context)
                            .map(|sub| sub.key().clone()),
                    );
                    return;
                }
                let now = Instant::now();
                let store = table.timed().clone();
                let claim = claim.insert(TimedClaim::new(store.clone()));
                let mut retained = Vec::new();
                for (sub, prepared) in candidates {
                    let Some(remaining) = table
                        .remaining_lifetime(sub, now)
                        .and_then(crate::cov::CovTimeRemaining::wire_seconds)
                    else {
                        continue;
                    };
                    let current = match prepared {
                        Ok((values, baseline, completion)) => {
                            retained.push((sub.clone(), values, baseline, completion, remaining));
                            continue;
                        }
                        Err(current) => current,
                    };
                    let Some(completion) = sub.prepare_completion() else {
                        continue;
                    };
                    // Captured changes carry their own commit times. The current
                    // state is conveyed as well only when it differs from the last
                    // captured or conveyed observation (a change no producer
                    // captured, such as a raw database mutation), stamped with
                    // this preparation's clock.
                    let mut timed = store.lock();
                    let (incarnation, mut changes) = timed.drain(sub.key(), sub.generation());
                    // The store baseline is the newest captured or conveyed state;
                    // a returned older change can sit at the tail of `changes`.
                    let baseline = timed
                        .baseline(sub.key(), sub.generation())
                        .cloned()
                        .or_else(|| changes.last().map(|change| change.observation().clone()))
                        .or_else(|| sub.last_notified_observation.clone());
                    // An admission capture already supplied the initial report.
                    let force = force
                        && changes.is_empty()
                        && timed.baseline(sub.key(), sub.generation()).is_none();
                    let current = current
                        .filter(|current| force || reads.reports(current, baseline.as_ref()));
                    match (current, clock_frame) {
                        (Some(prepared), Some(frame)) => {
                            let values = reads.with_flags_companion(
                                &sub.monitored_object_identifier,
                                prepared.values,
                            );
                            changes.push(timed.adopt(
                                sub.key(),
                                sub.generation(),
                                TimedChange::new(frame, values, prepared.observation),
                            ));
                        }
                        (Some(_), None) => warn!(
                            "Skipping timestamped COV-multiple change without a valid Device clock"
                        ),
                        (None, _) => {}
                    }
                    drop(timed);
                    let Some(last) = changes.last().map(|change| change.observation().clone())
                    else {
                        continue;
                    };
                    claim.add(sub.key().clone(), incarnation, changes);
                    retained.push((sub.clone(), Vec::new(), last, completion, remaining));
                }
                // Every notification to a context conveys all of its pending
                // timestamped changes (§§13.17.1.1, 13.18.1.1), including those
                // of references on objects that did not change now. A confirmed
                // context starts none while a report is outstanding, so this
                // holds for it too. Captured values need no object read.
                let mut untimed = HashSet::new();
                for other in table.multiple_context_references(&context) {
                    if !other.timestamped {
                        untimed.insert((
                            other.monitored_object_identifier,
                            other.monitored_property,
                            other.monitored_property_array_index,
                        ));
                        continue;
                    }
                    if subscriptions.iter().any(|sub| sub.key() == other.key()) {
                        continue;
                    }
                    let Some(remaining) = table
                        .remaining_lifetime(other, now)
                        .and_then(crate::cov::CovTimeRemaining::wire_seconds)
                    else {
                        continue;
                    };
                    let Some(completion) = other.prepare_completion() else {
                        continue;
                    };
                    let (incarnation, changes) =
                        store.lock().drain(other.key(), other.generation());
                    let Some(last) = changes.last().map(|change| change.observation().clone())
                    else {
                        continue;
                    };
                    claim.add(other.key().clone(), incarnation, changes);
                    retained.push((other.clone(), Vec::new(), last, completion, remaining));
                }
                (retained, untimed)
            };
            let claim = claim.as_mut().expect("claim created under the table guard");
            let Some((representative, _, _, _, time_remaining)) = retained.first() else {
                return;
            };
            let representative = representative.clone();
            let time_remaining = *time_remaining;
            let parts: Vec<_> = retained
                .iter()
                .map(|(sub, values, _, _, _)| (sub, values.as_slice()))
                .collect();
            // Fit the encoded request into one local APDU (confirmed header is
            // the larger form) by discarding the oldest queued history; the
            // latest change of every reference is always kept.
            let notification = loop {
                let notification = COVNotificationMultipleRequest {
                    subscriber_process_identifier: representative.subscriber_process_identifier,
                    initiating_device_identifier: device_oid,
                    time_remaining,
                    timestamp: claim.last_frame().map(cov_multiple_datetime),
                    list_of_cov_notifications: build_items(claim, &parts, &reads, &untimed),
                };
                let mut encoded = BytesMut::new();
                let fits = notification.encode(&mut encoded).is_err()
                    || encoded.len() + CONFIRMED_REQUEST_HEADER <= config.max_apdu_length as usize;
                if fits || !claim.drop_oldest_earlier() {
                    break notification;
                }
            };
            let last_notified: Vec<_> = retained
                .into_iter()
                .map(|(sub, _, baseline, completion, _)| (sub, baseline, completion))
                .collect();
            (notification, last_notified, representative)
        };

        // From the final live decision through fresh admission there is no await.
        if budget.is_exhausted() {
            counters
                .notifications_throttled_fanout
                .fetch_add(1, Ordering::Relaxed);
            return;
        }

        if representative.issue_confirmed_notifications {
            let max_apdu_length = apdu::max_apdu_header_at_or_below(config.max_apdu_length)
                .expect("validated local APDU capacity");
            Self::send_confirmed_cov(
                handles,
                budget,
                ConfirmedReport {
                    service: ConfirmedServiceChoice::CONFIRMED_COV_NOTIFICATION_MULTIPLE,
                    route: representative,
                    // The newest prepared ticket postdates every carried
                    // reference's baseline, so it completes them all.
                    completion: last_notified
                        .iter()
                        .map(|(_, _, completion)| *completion)
                        .max_by_key(|completion| completion.ticket())
                        .expect("a retained reference"),
                    observations: last_notified
                        .into_iter()
                        .map(|(sub, observation, _)| (sub, observation))
                        .collect(),
                    claim,
                },
                |invoke_id| {
                    Self::encode_confirmed_cov_multiple_apdu(
                        &notification,
                        invoke_id,
                        max_apdu_length,
                    )
                },
            )
            .await;
        } else {
            let buf = match Self::encode_unconfirmed_cov_multiple_apdu(&notification) {
                Ok(buf) => buf,
                Err(e) => {
                    warn!(error = %e, "Failed to encode unconfirmed COVNotificationMultiple");
                    return;
                }
            };

            if !budget.try_consume(buf.len()) {
                counters
                    .notifications_throttled_fanout
                    .fetch_add(1, Ordering::Relaxed);
                return;
            }

            counters.notifications_sent.fetch_add(1, Ordering::Relaxed);
            counters
                .notifications_unconfirmed
                .fetch_add(1, Ordering::Relaxed);
            counters
                .notification_bytes_sent
                .fetch_add(buf.len() as u64, Ordering::Relaxed);

            if let Err(e) = Self::send_cov_apdu(network, &buf, &representative, false).await {
                warn!(error = %e, "Failed to send COVNotificationMultiple");
            } else {
                if let Some(claim) = claim.take() {
                    claim.commit();
                }
                let mut table = cov_table.write().await;
                for (snapshot, pv, completion) in &last_notified {
                    table.complete_observation(snapshot, *completion, pv.clone());
                }
            }
        }
    }
}
