use super::*;
use bacnet_types::constructed::BACnetRecipient;
use bacnet_types::enums::EventType;

pub(super) struct NotificationTransition {
    change: EventStateChange,
    event_type: EventType,
}

impl From<(EventStateChange, EventType)> for NotificationTransition {
    fn from((change, event_type): (EventStateChange, EventType)) -> Self {
        Self { change, event_type }
    }
}

/// The DNET reserved for a global broadcast (Clause 6.3).
const GLOBAL_BROADCAST_NETWORK: u16 = 0xFFFF;

/// The network destination a Notification Class recipient resolves to.
///
/// Clause 21's `BACnetAddress` gives a recipient two independent knobs —
/// `network-number`, where "A value of 0 indicates the local network", and
/// `mac-address`, where "A string of length 0 indicates a broadcast" — and
/// Clause 6.3 reserves network 65535 for the global broadcast. Their
/// combinations are distinct sends rather than one unicast with edge cases,
/// which is why this is resolved once up front rather than decided at each
/// send site.
enum RecipientRoute {
    /// Network 0 with an explicit MAC: unicast on the local network.
    LocalUnicast(MacAddr),
    /// Network 0 with a zero-length MAC. Clause 12.21 prescribes exactly this
    /// recipient for a device whose `Recipient_List` is not writable and which
    /// uses no local Notification Forwarder objects.
    LocalBroadcast,
    /// A zero-length MAC on a remote network. Clause 6.3: "DNET shall specify
    /// the network number of the remote network and DLEN shall be set to zero".
    RemoteBroadcast(u16),
    /// A zero-length MAC on network 65535. Clause 6.3: "A global broadcast,
    /// indicated by a DNET of X'FFFF', is sent to all networks through all
    /// routers" — a destination of its own, not a remote network that happens
    /// to be numbered 65535. `broadcast_to_network` rejects 0xFFFF outright,
    /// so routing it as one would drop the notification.
    GlobalBroadcast,
    /// A unicast MAC on a remote network. Delivering it needs the MAC of a
    /// next-hop router, and no router table is reachable from the server, so
    /// the destination cannot be resolved. Tracked by #186.
    UnresolvedRoute(u16),
    /// A device-instance recipient. Resolving it needs a device-to-address
    /// binding this device does not maintain. Tracked by #125.
    UnresolvedDevice(ObjectIdentifier),
}

impl RecipientRoute {
    fn resolve(recipient: &BACnetRecipient) -> Self {
        match recipient {
            BACnetRecipient::Device(oid) => Self::UnresolvedDevice(*oid),
            BACnetRecipient::Address(addr) => {
                match (addr.network_number, addr.mac_address.is_empty()) {
                    (0, true) => Self::LocalBroadcast,
                    (0, false) => Self::LocalUnicast(addr.mac_address.clone()),
                    (GLOBAL_BROADCAST_NETWORK, true) => Self::GlobalBroadcast,
                    (net, true) => Self::RemoteBroadcast(net),
                    // Includes a MAC alongside network 65535, which is
                    // self-contradictory: a broadcast requires DLEN zero.
                    (net, false) => Self::UnresolvedRoute(net),
                }
            }
        }
    }

    /// Whether a ConfirmedEventNotification may be sent to this destination.
    ///
    /// Clause 6.3: "Of the BACnet APDUs, only the BACnet-Unconfirmed-Request-PDU
    /// may be transmitted using a multicast or broadcast network layer address".
    /// A confirmed notification also has nowhere to return its SimpleACK from.
    ///
    /// This recognizes only the *network-layer* spelling of a broadcast, the
    /// zero-length `mac-address`. A recipient carrying its data link's literal
    /// broadcast MAC — `X'FFFFFFFFFFFF'` on Ethernet, an all-ones host portion
    /// on BACnet/IP, `X'FF'` on MS/TP — reads as `LocalUnicast` here and is
    /// still sent confirmed. Recognizing those needs the transport's broadcast
    /// address, which this layer does not have. Tracked by #360.
    fn permits_confirmed(&self) -> bool {
        matches!(self, Self::LocalUnicast(_))
    }

    /// Whether this destination can be sent to at all, logging why not when it
    /// cannot. The two failures are reported separately because they are
    /// separate operator problems: an unreachable network is a routing
    /// configuration gap, while an unbound device instance is a recipient this
    /// device cannot address at all.
    fn is_deliverable(&self, notification_class: u32) -> bool {
        match self {
            Self::LocalUnicast(_)
            | Self::LocalBroadcast
            | Self::RemoteBroadcast(_)
            | Self::GlobalBroadcast => true,
            Self::UnresolvedRoute(network) => {
                warn!(
                    notification_class,
                    network, "Skipping recipient: no known route to its network"
                );
                false
            }
            Self::UnresolvedDevice(device) => {
                warn!(
                    notification_class,
                    %device,
                    "Skipping recipient: no address binding for this device instance"
                );
                false
            }
        }
    }
}

impl<T: TransportPort + 'static> BACnetServer<T> {
    /// Evaluate intrinsic reporting on an object and send event notifications
    /// to the recipients the object's NotificationClass names.
    /// DCC gates network-message initiation (Clause 16.1), not the local
    /// transition actions in Clause 13.2.2.1.4. The outbound sender below
    /// suppresses distribution while communications are disabled.
    ///
    /// This is the per-write entry point: it probes the detector, which fires
    /// immediately only when `Time_Delay == 0`. For a nonzero delay the probe
    /// seeds a pending transition (returning `None`, so no notification is
    /// sent here) and the one-second [`intrinsic_reporting_task`](Self::start)
    /// advances the countdown and sends the notification on expiry.
    pub(super) async fn fire_event_notifications(
        db: &Arc<RwLock<ObjectDatabase>>,
        network: &Arc<NetworkLayer<T>>,
        comm_state: &Arc<AtomicU8>,
        server_tsm: &Arc<Mutex<ServerTsm>>,
        oid: &ObjectIdentifier,
        retry_timeout_ms: u64,
    ) {
        let outcome = {
            let mut db = db.write().await;
            match db.get_mut(oid) {
                Some(object) => object.evaluate_intrinsic_reporting(),
                None => return,
            }
        };

        // The transition is already stored in Event_State by the detector,
        // whatever Event_Enable says. Only external distribution is gated here:
        // Clause 12.12 defines Event_Enable as enabling and disabling the
        // distribution of notifications, and Clause 13.2.5 places that gate
        // inside the notification-distribution process — downstream of the
        // transition actions, none of which it governs.
        //
        // Three of Clause 13.2.2.1.4's transition actions are still missing and
        // hook this same point, ahead of the `distribute` check: the
        // Event_Time_Stamps write, the Event_Message_Texts write (only "if
        // present"), and the indication to the alarm-acknowledgment process.
        // The first two are independent actions, not consequences of the third;
        // the third is what maintains Acked_Transitions, and Clause 13.2.3 gates
        // that on Ack_Required, never on Event_Enable. All tracked as #123.
        if let Some(outcome) = outcome {
            if outcome.distribute {
                Self::build_and_send_event_notification(
                    db,
                    network,
                    comm_state,
                    server_tsm,
                    oid,
                    (outcome.change, outcome.event_type),
                    retry_timeout_ms,
                )
                .await;
            }
        }
    }

    /// Build an `EventNotificationRequest` for a pre-computed transition and
    /// send it to the recipients the object's NotificationClass names.
    ///
    /// Shared by the per-write path ([`fire_event_notifications`]) and the
    /// periodic `Time_Delay` confirmation path, so both emit identical
    /// notifications. Skipped when DCC is active (comm_state >= 1). Re-reads
    /// `Notification_Class` / `Notify_Type` under a brief `db.write()` guard,
    /// then drops the lock before any network send.
    pub(super) async fn build_and_send_event_notification(
        db: &Arc<RwLock<ObjectDatabase>>,
        network: &Arc<NetworkLayer<T>>,
        comm_state: &Arc<AtomicU8>,
        server_tsm: &Arc<Mutex<ServerTsm>>,
        oid: &ObjectIdentifier,
        transition: impl Into<NotificationTransition>,
        retry_timeout_ms: u64,
    ) {
        if comm_state.load(Ordering::Acquire) >= 1 {
            return;
        }

        let NotificationTransition { change, event_type } = transition.into();
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default();
        let utc_secs = now.as_secs();

        let (notification, recipients) = {
            let mut db = db.write().await;

            let device_oid = db
                .list_objects()
                .into_iter()
                .find(|o| o.object_type() == ObjectType::DEVICE)
                .unwrap_or_else(|| ObjectIdentifier::new(ObjectType::DEVICE, 0).unwrap());

            // Project the wall clock into the device's local time using its
            // UTC_Offset property (signed minutes from UTC, Clause 12.32),
            // so the Recipient_List day/time filters are evaluated in the same
            // frame the device's schedule uses. With the default UTC_Offset of 0
            // this is a no-op (UTC).
            let utc_offset_minutes = db
                .get(&device_oid)
                .and_then(|dev| dev.read_property(PropertyIdentifier::UTC_OFFSET, None).ok())
                .and_then(|v| match v {
                    PropertyValue::Signed(m) => Some(m),
                    _ => None,
                })
                .unwrap_or(0);
            let (today_bit, mut current_time) = local_day_and_time(utc_secs, utc_offset_minutes);
            current_time.hundredths = (now.subsec_millis() / 10) as u8;

            let object = match db.get_mut(oid) {
                Some(o) => o,
                None => return,
            };

            let notification_class = object
                .read_property(PropertyIdentifier::NOTIFICATION_CLASS, None)
                .ok()
                .and_then(|v| match v {
                    PropertyValue::Unsigned(n) => Some(n as u32),
                    _ => None,
                })
                .unwrap_or(0);

            let notify_type = object
                .read_property(PropertyIdentifier::NOTIFY_TYPE, None)
                .ok()
                .and_then(|v| match v {
                    PropertyValue::Enumerated(n) => Some(n),
                    _ => None,
                })
                .unwrap_or(NotifyType::ALARM.to_raw());

            let transition = change.transition();

            // Resolve the per-transition Priority and Ack_Required from the
            // referenced NotificationClass (ASHRAE 135-2020 §13.2.1), falling
            // back to the BACnet defaults (Priority 255, no ack) when the
            // class is missing.
            let (priority, ack_required) =
                resolve_transition_priority_ack(&db, notification_class, transition);

            let base_notification = EventNotificationRequest {
                process_identifier: 0,
                initiating_device_identifier: device_oid,
                event_object_identifier: *oid,
                // Clause 21 constrains sequence-number to Unsigned (0..65535),
                // enforced by the shared timestamp codec on encode; wrap
                // seconds-of-epoch into the valid window.
                timestamp: BACnetTimeStamp::SequenceNumber(utc_secs % 65_536),
                notification_class,
                priority,
                event_type: event_type.to_raw(),
                message_text: None,
                notify_type,
                // ack_required is only meaningful for ALARM/EVENT notify types
                // (ACK_NOTIFICATION omits the field on the wire). Per §13.2.1 the
                // value is the NotificationClass's per-transition Ack_Required,
                // not a function of Notify_Type alone.
                ack_required: if notify_type == NotifyType::ACK_NOTIFICATION.to_raw() {
                    false
                } else {
                    ack_required
                },
                from_state: change.from.to_raw(),
                to_state: change.to.to_raw(),
                event_values: None,
            };

            let recipients = match get_notification_recipients_strict(
                &db,
                notification_class,
                transition,
                today_bit,
                &current_time,
            ) {
                Some(recipients) => recipients,
                None => {
                    // The NotificationClass's Recipient_List failed to
                    // decode — its configured recipients are UNKNOWN. Fail
                    // closed (consistent with the encode-failure branches
                    // below): deliver this notification to NO ONE rather
                    // than to a silently-truncated prefix of the configured
                    // destinations.
                    warn!(
                        notification_class,
                        "Recipient_List failed to decode; skipping event notification delivery"
                    );
                    return;
                }
            };

            (base_notification, recipients)
        };

        let notification_class = notification.notification_class;

        // Clause 13.2.5: "notifications are distributed to the notification-
        // clients specified by the Recipient_List input". The Recipient_List is
        // the destination set, so no matching recipient means no notification
        // is distributed. Broadcasting instead would invent a destination the
        // configuration never named, and would leak the alarm to every device
        // on the link.
        if recipients.is_empty() {
            debug!(
                notification_class,
                "No Recipient_List entry matched this transition; nothing distributed"
            );
            return;
        }

        for (recipient, process_id, confirmed) in &recipients {
            let route = RecipientRoute::resolve(recipient);

            if !route.is_deliverable(notification_class) {
                continue;
            }

            // Clause 6.3 restricts broadcast to Unconfirmed-Request-PDUs.
            // Downgrading to unconfirmed would drop the acknowledgment the
            // recipient was configured to require, so this is a skip.
            if *confirmed && !route.permits_confirmed() {
                warn!(
                    notification_class,
                    "Recipient requests confirmed notifications at a broadcast address; \
                     Clause 6.3 permits only unconfirmed PDUs there, skipping"
                );
                continue;
            }

            let mut targeted = notification.clone();
            targeted.process_identifier = *process_id;

            let mut service_buf = BytesMut::new();
            if let Err(e) = targeted.encode(&mut service_buf) {
                warn!(error = %e, "Failed to encode EventNotification");
                continue;
            }

            let service_bytes = service_buf.freeze();

            if *confirmed {
                // `permits_confirmed` above admits only `LocalUnicast`.
                let RecipientRoute::LocalUnicast(target_mac) = &route else {
                    continue;
                };
                let target_mac = target_mac.clone();
                let peer_key = (target_mac.clone(), None);
                let (id, result_rx) = match {
                    let mut tsm = server_tsm.lock().await;
                    tsm.allocate(peer_key.clone())
                } {
                    Some(allocated) => allocated,
                    None => {
                        warn!("No free invoke ID for confirmed EventNotification");
                        continue;
                    }
                };

                let pdu = Apdu::ConfirmedRequest(ConfirmedRequestPdu {
                    segmented: false,
                    more_follows: false,
                    segmented_response_accepted: false,
                    max_segments: None,
                    max_apdu_length: 1476,
                    invoke_id: id,
                    sequence_number: None,
                    proposed_window_size: None,
                    service_choice: ConfirmedServiceChoice::CONFIRMED_EVENT_NOTIFICATION,
                    service_request: service_bytes,
                });

                let mut buf = BytesMut::new();
                encode_apdu(&mut buf, &pdu).expect("valid APDU encoding");

                let network = Arc::clone(network);
                let tsm = Arc::clone(server_tsm);
                let timeout = Duration::from_millis(retry_timeout_ms);
                let apdu_retries = DEFAULT_APDU_RETRIES;
                tokio::spawn(async move {
                    let mut pending_rx: Option<oneshot::Receiver<CovAckResult>> = Some(result_rx);

                    for attempt in 0..=apdu_retries {
                        let send_result = network
                            .send_apdu(&buf, &target_mac, true, NetworkPriority::NORMAL)
                            .await;

                        if let Err(e) = send_result {
                            warn!(error = %e, attempt, "Confirmed EventNotification send failed");
                        } else {
                            debug!(invoke_id = id, attempt, "Confirmed EventNotification sent");
                        }

                        let rx = pending_rx
                            .take()
                            .expect("receiver always set for each attempt");
                        let result = match tokio::time::timeout(timeout, rx).await {
                            Ok(Ok(r)) => Ok(r),
                            Ok(Err(_)) => Err(()),
                            Err(_) => Err(()),
                        };

                        if result.is_err() && attempt < apdu_retries {
                            let new_rx = {
                                let mut tsm = tsm.lock().await;
                                tsm.register(peer_key.clone(), id)
                            };
                            pending_rx = Some(new_rx);
                        }

                        match result {
                            Ok(CovAckResult::Ack) => {
                                debug!(invoke_id = id, "EventNotification acknowledged");
                                return;
                            }
                            Ok(CovAckResult::Error) => {
                                warn!(invoke_id = id, "EventNotification rejected by recipient");
                                return;
                            }
                            Err(_) => {
                                if attempt < apdu_retries {
                                    debug!(
                                        invoke_id = id,
                                        attempt, "EventNotification timeout, retrying"
                                    );
                                } else {
                                    warn!(
                                        invoke_id = id,
                                        "EventNotification failed after {} retries", apdu_retries
                                    );
                                }
                            }
                        }
                    }

                    let mut tsm = tsm.lock().await;
                    tsm.remove(&peer_key, id);
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
                        network
                            .send_apdu(&buf, mac, false, NetworkPriority::NORMAL)
                            .await
                    }
                    RecipientRoute::LocalBroadcast => {
                        network
                            .broadcast_apdu(&buf, false, NetworkPriority::NORMAL)
                            .await
                    }
                    // Carries DNET with DLEN zero, so routers forward it
                    // onto the remote network as a broadcast there.
                    RecipientRoute::RemoteBroadcast(net) => {
                        network
                            .broadcast_to_network(&buf, *net, false, NetworkPriority::NORMAL)
                            .await
                    }
                    // Carries DNET 0xFFFF, which routers forward to every
                    // reachable network. `broadcast_to_network` rejects that
                    // DNET, so it needs its own send.
                    RecipientRoute::GlobalBroadcast => {
                        network
                            .broadcast_global_apdu(&buf, false, NetworkPriority::NORMAL)
                            .await
                    }
                    // Filtered out by `RecipientRoute::is_deliverable` above.
                    RecipientRoute::UnresolvedRoute(_) | RecipientRoute::UnresolvedDevice(_) => {
                        continue
                    }
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
