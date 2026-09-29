use super::cov_clock::cov_multiple_datetime;
use super::*;
use crate::cov::multiple_reads::MultipleReads;
use crate::cov::timed::{TimedChange, TimedClaim};

impl<T: TransportPort + 'static> BACnetServer<T> {
    /// Fire the initial COVNotificationMultiple for a newly accepted
    /// SubscribeCOVPropertyMultiple request.
    #[allow(clippy::too_many_arguments)]
    pub(in crate::server) async fn fire_initial_cov_notification_multiple(
        db: &Arc<RwLock<ObjectDatabase>>,
        network: &Arc<NetworkLayer<T>>,
        cov_table: &Arc<RwLock<CovSubscriptionTable>>,
        cov_in_flight: &Arc<Semaphore>,
        notification_transactions: &Arc<NotificationTransactions>,
        comm_state: &Arc<AtomicU8>,
        config: &ServerConfig,
        subscriptions: &[CovSubscriptionSnapshot],
    ) {
        let (counters, in_flight_tracker, subscriptions) = {
            let table = cov_table.read().await;
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
        let mut budget = EventBudget::new(&config.cov_policy);
        Self::fire_cov_notification_multiple_for_subscriptions(
            db,
            network,
            cov_table,
            cov_in_flight,
            &in_flight_tracker,
            &counters,
            notification_transactions,
            comm_state,
            config,
            None,
            &subscriptions,
            None,
            true,
            &mut budget,
        )
        .await;
    }

    #[allow(clippy::too_many_arguments)]
    pub(in crate::server) async fn fire_cov_notification_multiple_for_subscriptions(
        db: &Arc<RwLock<ObjectDatabase>>,
        network: &Arc<NetworkLayer<T>>,
        cov_table: &Arc<RwLock<CovSubscriptionTable>>,
        cov_in_flight: &Arc<Semaphore>,
        in_flight_tracker: &Arc<CovInFlightTracker>,
        counters: &Arc<AtomicCovCounters>,
        notification_transactions: &Arc<NotificationTransactions>,
        comm_state: &Arc<AtomicU8>,
        config: &ServerConfig,
        changed_oid: Option<&ObjectIdentifier>,
        subscriptions: &[CovSubscriptionSnapshot],
        snapshot: Option<&dyn bacnet_objects::traits::BACnetObject>,
        force: bool,
        budget: &mut EventBudget,
    ) {
        if comm_state.load(Ordering::Acquire) >= 1 || subscriptions.is_empty() {
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
            Self::send_cov_notification_multiple(
                db,
                network,
                cov_table,
                cov_in_flight,
                in_flight_tracker,
                counters,
                notification_transactions,
                config,
                subs,
                snapshot,
                force || changed_oid.is_none(),
                budget,
            )
            .await;
        }
    }

    #[allow(clippy::too_many_arguments)]
    async fn send_cov_notification_multiple(
        db: &Arc<RwLock<ObjectDatabase>>,
        network: &Arc<NetworkLayer<T>>,
        cov_table: &Arc<RwLock<CovSubscriptionTable>>,
        cov_in_flight: &Arc<Semaphore>,
        in_flight_tracker: &Arc<CovInFlightTracker>,
        counters: &Arc<AtomicCovCounters>,
        notification_transactions: &Arc<NotificationTransactions>,
        config: &ServerConfig,
        subscriptions: &[CovSubscriptionSnapshot],
        snapshot: Option<&dyn bacnet_objects::traits::BACnetObject>,
        force: bool,
        budget: &mut EventBudget,
    ) {
        if subscriptions.is_empty() {
            return;
        }

        // Timestamped changes drained for this notification; dropping the claim
        // without commit (any early return, failed send) requeues them.
        let mut claim: Option<TimedClaim> = None;
        let (device_oid, items, last_notified, representative, time_remaining, timestamp) = {
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
            let retained: Vec<_> = {
                let table = cov_table.read().await;
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
                            retained.push((sub, values, baseline, completion, remaining));
                            continue;
                        }
                        Err(current) => current,
                    };
                    // Captured changes carry their own commit times. The current
                    // state is conveyed as well only when it differs from the last
                    // captured or conveyed observation (a producer without capture),
                    // stamped with this preparation's clock.
                    let mut timed = store.lock();
                    let mut changes = timed.drain(sub.key(), sub.generation());
                    let baseline = changes
                        .last()
                        .map(|change| change.observation().clone())
                        .or_else(|| timed.baseline(sub.key(), sub.generation()).cloned())
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
                    let completion = sub.prepare_completion();
                    claim.add(sub.key().clone(), sub.generation(), changes);
                    if let Some(completion) = completion {
                        retained.push((sub, Vec::new(), last, completion, remaining));
                    }
                }
                retained
            };
            let claim = claim.as_mut().expect("claim created under the table guard");
            claim.fit();
            let claim = &*claim;
            let Some((representative, _, _, _, time_remaining)) = retained.first() else {
                return;
            };
            let representative = *representative;
            let time_remaining = *time_remaining;
            let mut items: Vec<COVNotificationItem> = Vec::new();
            let mut last_notified = Vec::new();
            let item_for = |items: &mut Vec<COVNotificationItem>, oid: ObjectIdentifier| {
                items
                    .iter()
                    .position(|item| item.monitored_object_identifier == oid)
                    .unwrap_or_else(|| {
                        items.push(COVNotificationItem {
                            monitored_object_identifier: oid,
                            list_of_values: Vec::new(),
                        });
                        items.len() - 1
                    })
            };
            // Queued history first: every earlier timestamped change as distinct
            // values with its own time (repeated coordinates are permitted).
            for (key, change) in claim.earlier() {
                let index = item_for(&mut items, key.object());
                let list = &mut items[index].list_of_values;
                for value in change.values() {
                    if !list.contains(value) {
                        list.push(value.clone());
                    }
                }
            }
            let history: Vec<usize> = items.iter().map(|item| item.list_of_values.len()).collect();
            // Current state: one value per coordinate. A timestamped reference
            // contributes its latest change stamped with that change's own time.
            let latest_time = |sub: &CovSubscriptionSnapshot| {
                claim
                    .latest(sub.key())
                    .map(|change| change.frame().local_time)
            };
            let mut retained_subscriptions = Vec::new();
            for (sub, values, baseline, completion, _) in retained {
                last_notified.push((sub.clone(), baseline, completion));
                retained_subscriptions.push(sub);
                let values = if sub.timestamped {
                    claim
                        .latest(sub.key())
                        .map(|change| change.values().to_vec())
                        .unwrap_or_default()
                } else {
                    values
                };
                let index = item_for(&mut items, sub.monitored_object_identifier);
                let start = history.get(index).copied().unwrap_or(0);
                for value in values {
                    let current = &mut items[index].list_of_values[start..];
                    if let Some(existing) = current.iter_mut().find(|v| {
                        v.property_identifier == value.property_identifier
                            && v.property_array_index == value.property_array_index
                    }) {
                        existing.time_of_change = existing.time_of_change.or(value.time_of_change);
                    } else {
                        items[index].list_of_values.push(value);
                    }
                }
            }
            for (index, item) in items.iter_mut().enumerate() {
                let start = history.get(index).copied().unwrap_or(0);
                if item.list_of_values[start..]
                    .iter()
                    .any(|v| v.property_identifier == PropertyIdentifier::STATUS_FLAGS)
                {
                    continue;
                }
                if let Some(encoded) = reads.encoded_flags(&item.monitored_object_identifier) {
                    item.list_of_values.push(COVNotificationValue {
                        property_identifier: PropertyIdentifier::STATUS_FLAGS,
                        property_array_index: None,
                        value: encoded.to_vec(),
                        time_of_change: None,
                    });
                }
            }
            // Qualified explicit selectors control their own current coordinate.
            // OR above combines only implicit companion intent; an explicit false
            // remains false. Unqualified references have no entry in this list.
            for sub in &retained_subscriptions {
                let Some(index) = items.iter().position(|item| {
                    item.monitored_object_identifier == sub.monitored_object_identifier
                }) else {
                    continue;
                };
                let start = history.get(index).copied().unwrap_or(0);
                if let Some(value) = items[index].list_of_values[start..]
                    .iter_mut()
                    .find(|value| {
                        Some(value.property_identifier) == sub.monitored_property
                            && value.property_array_index == sub.monitored_property_array_index
                    })
                {
                    value.time_of_change = sub.timestamped.then(|| latest_time(sub)).flatten();
                }
            }
            let timestamp = claim.last_frame().map(cov_multiple_datetime);
            (
                device_oid,
                items,
                last_notified,
                representative,
                time_remaining,
                timestamp,
            )
        };

        // From the final live decision through fresh admission there is no await.
        if budget.is_exhausted() {
            counters
                .notifications_throttled_fanout
                .fetch_add(1, Ordering::Relaxed);
            return;
        }

        let notification = COVNotificationMultipleRequest {
            subscriber_process_identifier: representative.subscriber_process_identifier,
            initiating_device_identifier: device_oid,
            time_remaining,
            timestamp,
            list_of_cov_notifications: items,
        };

        if representative.issue_confirmed_notifications {
            let guard = match in_flight_tracker.try_acquire(
                representative.recipient(),
                config.cov_policy.max_confirmed_in_flight_per_peer,
                cov_in_flight,
            ) {
                Ok(guard) => guard,
                Err(InFlightAcquireError::PeerLimitExceeded) => {
                    counters
                        .notifications_throttled_peer
                        .fetch_add(1, Ordering::Relaxed);
                    return;
                }
                Err(InFlightAcquireError::GlobalPoolExhausted) => {
                    warn!("255 confirmed COV notifications in-flight, skipping COVNotificationMultiple");
                    return;
                }
            };

            let (operation, result_rx) = match notification_transactions.reserve(
                Self::canonical_cov_peer(representative),
                ConfirmedServiceChoice::CONFIRMED_COV_NOTIFICATION_MULTIPLE,
            ) {
                Ok(reservation) => reservation,
                Err(error) => {
                    warn!(%error, "No free invoke ID for confirmed COVNotificationMultiple");
                    return;
                }
            };
            let id = operation.invoke_id();

            let buf = match Self::encode_confirmed_cov_multiple_apdu(
                &notification,
                id,
                apdu::max_apdu_header_at_or_below(config.max_apdu_length)
                    .expect("validated local APDU capacity"),
            ) {
                Ok(buf) => buf,
                Err(e) => {
                    warn!(error = %e, "Failed to encode confirmed COVNotificationMultiple");
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
                .notifications_confirmed
                .fetch_add(1, Ordering::Relaxed);
            counters
                .notification_bytes_sent
                .fetch_add(buf.len() as u64, Ordering::Relaxed);

            {
                let mut table = cov_table.write().await;
                for (snapshot, pv, completion) in &last_notified {
                    table.complete_observation(snapshot, *completion, pv.clone());
                }
            }

            let network = Arc::clone(network);
            let sub = representative.clone();
            let apdu_timeout = Duration::from_millis(config.cov_retry_timeout_ms);
            let apdu_retries = DEFAULT_APDU_RETRIES;
            // Timestamped changes retire at the first transmitted attempt; a
            // worker that never transmits requeues them when the claim drops.
            let claim = Arc::new(std::sync::Mutex::new(claim));
            notification_transactions.spawn(async move {
                let _guard = guard;
                let result = run_notification_worker(
                    operation,
                    result_rx,
                    apdu_timeout,
                    apdu_retries,
                    |attempt| {
                        let network = Arc::clone(&network);
                        let buf = buf.clone();
                        let sub = sub.clone();
                        let claim = Arc::clone(&claim);
                        async move {
                            let result = Self::send_cov_apdu(&network, &buf, &sub, true).await;
                            if result.is_ok() {
                                let transmitted = claim
                                    .lock()
                                    .unwrap_or_else(|poison| poison.into_inner())
                                    .take();
                                if let Some(transmitted) = transmitted {
                                    transmitted.commit();
                                }
                            }
                            match &result {
                                Ok(()) => debug!(
                                    invoke_id = id,
                                    attempt, "Confirmed COVNotificationMultiple sent"
                                ),
                                Err(error) => warn!(
                                    %error,
                                    attempt, "COVNotificationMultiple send failed"
                                ),
                            }
                            result
                        }
                    },
                )
                .await;
                match result {
                    NotificationWorkerResult::Ack => {
                        debug!(invoke_id = id, "COVNotificationMultiple acknowledged");
                    }
                    NotificationWorkerResult::Error => warn!(
                        invoke_id = id,
                        "COVNotificationMultiple rejected by subscriber"
                    ),
                    NotificationWorkerResult::Exhausted => warn!(
                        invoke_id = id,
                        "COVNotificationMultiple failed after {} retries", apdu_retries
                    ),
                    NotificationWorkerResult::Closed => {}
                }
            });
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

            if let Err(e) = Self::send_cov_apdu(network, &buf, representative, false).await {
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
