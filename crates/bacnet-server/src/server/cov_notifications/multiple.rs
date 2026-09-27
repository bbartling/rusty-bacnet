use super::cov_clock::cov_multiple_datetime;
use super::*;

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

        let (device_oid, clock_frame) = {
            let db = db.read().await;
            let device_oid = crate::local_device::selected_device(&db)
                .unwrap_or_else(|| ObjectIdentifier::new(ObjectType::DEVICE, 0).unwrap());
            let clock_frame = subscriptions
                .iter()
                .any(|sub| sub.timestamped)
                .then(|| db.clock_frame())
                .flatten();
            (device_oid, clock_frame)
        };
        let (items, last_notified, representative, time_remaining, timestamp) = {
            let db = if snapshot.is_none() {
                Some(db.read().await)
            } else {
                None
            };
            let mut candidates = Vec::new();
            // One capture per object in this context; all selected values and
            // companions share this DB/snapshot borrow, never a cross-context cache.
            let mut flags_by_object = HashMap::new();
            let mut sources_by_object = HashMap::new();
            for sub in subscriptions {
                let Some(object) = snapshot
                    .filter(|object| object.object_identifier() == sub.monitored_object_identifier)
                    .or_else(|| db.as_deref()?.get(&sub.monitored_object_identifier))
                else {
                    continue;
                };
                if sub.monitored_property != Some(PropertyIdentifier::VALUE_SOURCE)
                    || !crate::cov::value_source::applies(object, PropertyIdentifier::VALUE_SOURCE)
                {
                    continue;
                }
                let flags = flags_by_object
                    .entry(sub.monitored_object_identifier)
                    .or_insert_with(|| crate::cov::flags::PreparedFlags::read(object));
                if let Ok(flags) = flags {
                    sources_by_object
                        .entry(sub.monitored_object_identifier)
                        .or_insert_with(|| {
                            crate::cov::value_source::PreparedValueSource::read(object, flags)
                        });
                }
            }
            for sub in subscriptions {
                let Some(property_identifier) = sub.monitored_property else {
                    continue;
                };
                let Some(object) = snapshot
                    .filter(|object| object.object_identifier() == sub.monitored_object_identifier)
                    .or_else(|| db.as_deref()?.get(&sub.monitored_object_identifier))
                else {
                    continue;
                };
                let flags = flags_by_object
                    .entry(sub.monitored_object_identifier)
                    .or_insert_with(|| crate::cov::flags::PreparedFlags::read(object));
                let Ok(flags) = flags else {
                    continue;
                };
                if crate::cov::value_source::applies(object, property_identifier) {
                    if sub.monitored_property_array_index.is_some() {
                        continue;
                    }
                    let Some(Ok(prepared)) =
                        sources_by_object.get(&sub.monitored_object_identifier)
                    else {
                        continue;
                    };
                    if !force && !prepared.reports(sub.last_notified_observation.as_ref()) {
                        continue;
                    }
                    candidates.push((
                        sub,
                        prepared
                            .values()
                            .into_iter()
                            .map(|value| COVNotificationValue {
                                property_identifier: value.property_identifier,
                                property_array_index: value.property_array_index,
                                value: value.value,
                                time_of_change: None,
                            })
                            .collect::<Vec<_>>(),
                        prepared.observation.clone(),
                    ));
                    continue;
                }
                let prepared = if property_identifier == PropertyIdentifier::STATUS_FLAGS {
                    flags.selected(object, sub.monitored_property_array_index)
                } else {
                    let captured = sources_by_object
                        .get(&sub.monitored_object_identifier)
                        .and_then(|source| source.as_ref().ok())
                        .filter(|_| sub.monitored_property_array_index.is_none())
                        .and_then(|source| source.value(property_identifier));
                    captured
                        .cloned()
                        .map(Ok)
                        .unwrap_or_else(|| {
                            object.read_property(
                                property_identifier,
                                sub.monitored_property_array_index,
                            )
                        })
                        .and_then(|value| {
                            crate::cov::prepare::prepare_value(
                                object,
                                property_identifier,
                                sub.monitored_property_array_index,
                                sub.cov_increment,
                                &value,
                            )
                        })
                };
                let Ok(prepared) = prepared else {
                    continue;
                };
                let observation = flags.observation(prepared.sample.clone());
                if !force
                    && !prepared.reports(sub.last_notified_observation.as_ref().map(|o| o.sample()))
                    && !observation.flags_changed(sub.last_notified_observation.as_ref())
                {
                    continue;
                }
                candidates.push((
                    sub,
                    vec![COVNotificationValue {
                        property_identifier,
                        property_array_index: sub.monitored_property_array_index,
                        value: prepared.encoded,
                        time_of_change: None,
                    }],
                    observation,
                ));
            }

            // Established lock order: DB read -> table read. No object callback
            // runs under the table guard. Each prepared value owns its own check;
            // a live sibling with a failed read cannot authorize a stale value.
            let retained: Vec<_> = {
                let table = cov_table.read().await;
                let now = Instant::now();
                candidates
                    .into_iter()
                    .filter_map(|(sub, value, baseline)| {
                        table
                            .remaining_lifetime(sub, now)
                            .and_then(crate::cov::CovTimeRemaining::wire_seconds)
                            .map(|remaining| (sub, value, baseline, remaining))
                    })
                    .collect()
            };
            let Some((representative, _, _, time_remaining)) = retained.first() else {
                return;
            };
            let representative = *representative;
            let time_remaining = *time_remaining;
            let timestamp = if retained.iter().any(|(sub, _, _, _)| sub.timestamped) {
                match clock_frame {
                    Some(frame) if frame.is_valid_actual_datetime() => {
                        Some(cov_multiple_datetime(frame))
                    }
                    _ => {
                        warn!("Skipping timestamped COVNotificationMultiple without a valid Device clock");
                        return;
                    }
                }
            } else {
                None
            };
            let mut items: Vec<COVNotificationItem> = Vec::new();
            let mut last_notified = Vec::new();
            let mut retained_subscriptions = Vec::new();
            for (sub, mut values, baseline, _) in retained {
                for value in &mut values {
                    value.time_of_change = sub
                        .timestamped
                        .then(|| timestamp.map(|(_, time)| time))
                        .flatten();
                }
                last_notified.push((sub.clone(), baseline));
                retained_subscriptions.push(sub.clone());
                let item_index = items
                    .iter()
                    .position(|item| {
                        item.monitored_object_identifier == sub.monitored_object_identifier
                    })
                    .unwrap_or_else(|| {
                        items.push(COVNotificationItem {
                            monitored_object_identifier: sub.monitored_object_identifier,
                            list_of_values: Vec::new(),
                        });
                        items.len() - 1
                    });
                for value in values {
                    if let Some(existing) = items[item_index].list_of_values.iter_mut().find(|v| {
                        v.property_identifier == value.property_identifier
                            && v.property_array_index == value.property_array_index
                    }) {
                        existing.time_of_change = existing.time_of_change.or(value.time_of_change);
                    } else {
                        items[item_index].list_of_values.push(value);
                    }
                }
            }
            for item in &mut items {
                // A shared flags field inherits time from any qualified
                // reference contributing that companion, even if a non-timestamped
                // source report already supplied the same field.
                let time_of_change = retained_subscriptions
                    .iter()
                    .any(|sub| {
                        sub.monitored_object_identifier == item.monitored_object_identifier
                            && sub.timestamped
                    })
                    .then(|| timestamp.map(|(_, time)| time))
                    .flatten();
                if let Some(existing) = item
                    .list_of_values
                    .iter_mut()
                    .find(|v| v.property_identifier == PropertyIdentifier::STATUS_FLAGS)
                {
                    existing.time_of_change = existing.time_of_change.or(time_of_change);
                    continue;
                }
                let Some(Ok(flags)) = flags_by_object.get(&item.monitored_object_identifier) else {
                    continue;
                };
                if let Some(encoded) = &flags.encoded {
                    item.list_of_values.push(COVNotificationValue {
                        property_identifier: PropertyIdentifier::STATUS_FLAGS,
                        property_array_index: None,
                        value: encoded.clone(),
                        time_of_change,
                    });
                }
            }
            // Qualified explicit selectors control their own coordinates. OR
            // above combines only implicit companion intent; an explicit false
            // remains false. Unqualified references have no entry in this list.
            for sub in &retained_subscriptions {
                if let Some(value) = items
                    .iter_mut()
                    .find(|item| {
                        item.monitored_object_identifier == sub.monitored_object_identifier
                    })
                    .and_then(|item| {
                        item.list_of_values.iter_mut().find(|value| {
                            Some(value.property_identifier) == sub.monitored_property
                                && value.property_array_index == sub.monitored_property_array_index
                        })
                    })
                {
                    value.time_of_change = sub
                        .timestamped
                        .then(|| timestamp.map(|(_, time)| time))
                        .flatten();
                }
            }
            (
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
                config.max_apdu_length as u16,
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
                for (snapshot, pv) in &last_notified {
                    table.set_last_notified_observation(snapshot, pv.clone());
                }
            }

            let network = Arc::clone(network);
            let sub = representative.clone();
            let apdu_timeout = Duration::from_millis(config.cov_retry_timeout_ms);
            let apdu_retries = DEFAULT_APDU_RETRIES;
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
                        async move {
                            let result = Self::send_cov_apdu(&network, &buf, &sub, true).await;
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
                let mut table = cov_table.write().await;
                for (snapshot, pv) in &last_notified {
                    table.set_last_notified_observation(snapshot, pv.clone());
                }
            }
        }
    }
}
