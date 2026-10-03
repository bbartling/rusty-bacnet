//! The one EventNotification send path: each notification this server
//! originates, and each copy its Notification Forwarders send on, reaches
//! its recipients through [`BACnetServer::send_event_notification`].

use super::event_recipient_route::{
    network_priority_for_event, ConfirmedRecipientRoute, RecipientRoute,
};
use super::event_suppression::EventSuppression;
use super::notification_transactions::NotificationReserveError;
use super::*;
use bacnet_types::constructed::BACnetRecipient;

/// The service request a notification sends to one process identifier.
pub(super) type EncodeFor<'a> = &'a (dyn Fn(u32) -> Result<Bytes, Error> + Send + Sync);

/// Whether a notification may take a resolved route.
pub(super) type AdmitsRoute<'a> = &'a (dyn Fn(&RecipientRoute) -> bool + Send + Sync);

/// One event notification on its way to its recipients.
pub(super) struct OutboundNotification<'a> {
    /// The notification class, named in diagnostics.
    pub(super) notification_class: u32,
    /// The event priority, which sets the NPDU priority of every send and
    /// retry (Clause 13.2.5.4).
    pub(super) priority: u8,
    /// The request for each destination's process identifier.
    pub(super) encode_for: EncodeFor<'a>,
    /// Routes the notification may take. A refused route is skipped and not
    /// counted; the server's own notifications admit every route.
    pub(super) admits: AdmitsRoute<'a>,
}

impl<T: TransportPort + 'static> BACnetServer<T> {
    /// Send `outbound` to each recipient, confirmed or not as the recipient
    /// asks. A recipient whose route cannot carry the notification is
    /// skipped and counted in [`EventNotificationCounters`]; the rest are
    /// still served. Nothing is sent while DeviceCommunicationControl
    /// restricts initiation.
    pub(super) async fn send_event_notification(
        ctx: &EventDelivery<'_, T>,
        outbound: &OutboundNotification<'_>,
        recipients: &[(BACnetRecipient, u32, bool)],
    ) {
        let &EventDelivery {
            db: _,
            network,
            comm_state,
            learned_routers,
            notification_transactions,
            device_bindings,
            suppressions,
            retry_timeout_ms,
            local_apdu_capacity,
        } = ctx;
        if comm_state.load(Ordering::Acquire) >= 1 {
            return;
        }
        let notification_class = outbound.notification_class;
        let network_priority = network_priority_for_event(outbound.priority);

        for (recipient, process_id, confirmed) in recipients {
            let route = match recipient {
                BACnetRecipient::Address(address) => {
                    RecipientRoute::resolve_address(address, |mac| {
                        network.transport().is_broadcast_mac(mac)
                    })
                }
                BACnetRecipient::Device(identifier) => {
                    let resolution = {
                        let table = device_bindings.read().await;
                        table.resolve_at(identifier, Instant::now(), |mac| {
                            network.transport().is_broadcast_mac(mac)
                        })
                    };
                    RecipientRoute::from_device_resolution(resolution)
                }
            };

            // A route that can't carry this notification is skipped and
            // counted (#1160); the remaining destinations are still served.
            if let Some(skip) = route.skip(*confirmed, notification_class) {
                suppressions.record(skip);
                continue;
            }
            // A forwarded notification keeps off the routes Clause 12.51's
            // loop rules close to it. That is configured behaviour, not a
            // failed delivery, so nothing is counted.
            if !(outbound.admits)(&route) {
                debug!(
                    notification_class,
                    "Forwarding rule keeps the notification off this route"
                );
                continue;
            }

            let service_bytes = match (outbound.encode_for)(*process_id) {
                Ok(bytes) => bytes,
                Err(e) => {
                    warn!(error = %e, "Failed to encode EventNotification");
                    continue;
                }
            };

            if *confirmed {
                // Convert only the unicast route shapes admitted above and
                // fail closed if the route classification changes.
                let Some(ConfirmedRecipientRoute {
                    canonical_peer,
                    local_target,
                    remote,
                    freshness,
                }) = route.into_confirmed()
                else {
                    warn!(
                        notification_class,
                        "Confirmed notification route is unusable"
                    );
                    continue;
                };
                let (operation, result_rx) = match notification_transactions.reserve(
                    canonical_peer,
                    ConfirmedServiceChoice::CONFIRMED_EVENT_NOTIFICATION,
                ) {
                    Ok(reservation) => reservation,
                    // Stopping closes the adapter, which is not a delivery
                    // failure, so it is not counted.
                    Err(NotificationReserveError::Closed) => {
                        debug!("Server stopping; confirmed EventNotification not sent");
                        continue;
                    }
                    Err(error) => {
                        suppressions.record(EventSuppression::ConfirmedNoInvokeId);
                        warn!(%error, "No free invoke ID for confirmed EventNotification");
                        continue;
                    }
                };
                let id = operation.invoke_id();

                let pdu = Apdu::ConfirmedRequest(ConfirmedRequestPdu {
                    segmented: false,
                    more_follows: false,
                    segmented_response_accepted: false,
                    max_segments: None,
                    max_apdu_length: apdu::max_apdu_header_at_or_below(local_apdu_capacity)
                        .expect("validated local APDU capacity"),
                    invoke_id: id,
                    sequence_number: None,
                    proposed_window_size: None,
                    service_choice: ConfirmedServiceChoice::CONFIRMED_EVENT_NOTIFICATION,
                    service_request: service_bytes,
                });

                let mut buf = BytesMut::new();
                encode_apdu(&mut buf, &pdu).expect("valid APDU encoding");

                let network = Arc::clone(network);
                let learned_routers = Arc::clone(learned_routers);
                let suppressions = Arc::clone(suppressions);
                let timeout = Duration::from_millis(retry_timeout_ms);
                let apdu_retries = DEFAULT_APDU_RETRIES;
                notification_transactions.spawn(async move {
                    let result = run_notification_worker(
                        operation,
                        result_rx,
                        timeout,
                        apdu_retries,
                        |attempt| {
                            let network = Arc::clone(&network);
                            let learned_routers = Arc::clone(&learned_routers);
                            let buf = buf.clone();
                            let local_target = local_target.clone();
                            let remote = remote.clone();
                            async move {
                                if freshness.is_some_and(|freshness| {
                                    !freshness.permits_attempt_at(tokio::time::Instant::now())
                                }) {
                                    debug!(
                                        invoke_id = id,
                                        attempt,
                                        "Observed Device binding expired before notification attempt"
                                    );
                                    return Err(());
                                }
                                let send_result = match (local_target, remote) {
                                    (Some(target), None) => {
                                        network
                                            .send_apdu(&buf, &target, true, network_priority)
                                            .await
                                    }
                                    (None, Some((dnet, dadr, configured_router))) => {
                                        // A Device binding keeps its fixed next hop for
                                        // each permitted attempt. Address recipients retain
                                        // the learned-router/broadcast behavior.
                                        let router = match configured_router {
                                            Some(router) => Some(router),
                                            None if attempt == 0 => {
                                                learned_routers.lock().await.cached_router(dnet)
                                            }
                                            None => None,
                                        };
                                        match router {
                                            Some(router_mac) => {
                                                network
                                                    .send_apdu_routed(
                                                        &buf,
                                                        dnet,
                                                        &dadr,
                                                        &router_mac,
                                                        true,
                                                        network_priority,
                                                    )
                                                    .await
                                            }
                                            None => {
                                                network
                                                    .send_apdu_routed_via_local_broadcast(
                                                        &buf,
                                                        dnet,
                                                        &dadr,
                                                        true,
                                                        network_priority,
                                                    )
                                                    .await
                                            }
                                        }
                                    }
                                    _ => unreachable!("confirmed route validated before spawn"),
                                };
                                match &send_result {
                                    Ok(()) => debug!(
                                        invoke_id = id,
                                        attempt, "Confirmed EventNotification sent"
                                    ),
                                    Err(error) => warn!(
                                        %error,
                                        attempt, "Confirmed EventNotification send failed"
                                    ),
                                }
                                send_result.map_err(|_| ())
                            }
                        },
                    )
                    .await;
                    match result {
                        NotificationWorkerResult::Ack => {
                            debug!(invoke_id = id, "EventNotification acknowledged");
                        }
                        NotificationWorkerResult::Error => {
                            suppressions.record(EventSuppression::ConfirmedRejected);
                            warn!(invoke_id = id, "EventNotification rejected by recipient");
                        }
                        NotificationWorkerResult::Exhausted => {
                            suppressions.record(EventSuppression::ConfirmedUnanswered);
                            warn!(
                                invoke_id = id,
                                "EventNotification failed after {} retries", apdu_retries
                            );
                        }
                        NotificationWorkerResult::Closed => {}
                    }
                });
            } else {
                let pdu = Apdu::UnconfirmedRequest(UnconfirmedRequestPdu {
                    service_choice: UnconfirmedServiceChoice::UNCONFIRMED_EVENT_NOTIFICATION,
                    service_request: service_bytes,
                });

                let mut buf = BytesMut::new();
                encode_apdu(&mut buf, &pdu).expect("valid APDU encoding");

                let send_result = match &route {
                    RecipientRoute::LocalUnicast(mac) => {
                        network.send_apdu(&buf, mac, false, network_priority).await
                    }
                    RecipientRoute::BoundLocalUnicast { mac, .. } => {
                        network.send_apdu(&buf, mac, false, network_priority).await
                    }
                    RecipientRoute::LocalBroadcast => {
                        network.broadcast_apdu(&buf, false, network_priority).await
                    }
                    // Carries DNET with DLEN zero, so routers forward it
                    // onto the remote network as a broadcast there.
                    RecipientRoute::RemoteBroadcast(net) => {
                        network
                            .broadcast_to_network(&buf, *net, false, network_priority)
                            .await
                    }
                    // Carries DNET 0xFFFF, which routers forward to every
                    // reachable network. `broadcast_to_network` rejects that
                    // DNET, so it needs its own send.
                    RecipientRoute::GlobalBroadcast => {
                        network
                            .broadcast_global_apdu(&buf, false, network_priority)
                            .await
                    }
                    // DNET/DADR name the recipient; the link DA is the local
                    // broadcast because this non-routing device keeps no
                    // router table (Clause 6.5.3's unknown-router form).
                    RecipientRoute::RemoteUnicast { network: net, mac } => {
                        network
                            .send_apdu_routed_via_local_broadcast(
                                &buf,
                                *net,
                                mac,
                                false,
                                network_priority,
                            )
                            .await
                    }
                    RecipientRoute::BoundRoutedUnicast {
                        network: net,
                        mac,
                        router,
                        ..
                    } => {
                        network
                            .send_apdu_routed(&buf, *net, mac, router, false, network_priority)
                            .await
                    }
                    // Skipped by `RecipientRoute::skip` above.
                    RecipientRoute::ContradictoryGlobal
                    | RecipientRoute::UnknownDevice
                    | RecipientRoute::StaleDevice
                    | RecipientRoute::InvalidDevice => continue,
                };

                if let Err(e) = send_result {
                    warn!(
                        error = %e,
                        "Failed to send unconfirmed EventNotification"
                    );
                }
            }
        }
    }
}
