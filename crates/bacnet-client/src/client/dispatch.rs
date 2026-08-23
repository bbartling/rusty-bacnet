use super::*;
use crate::tsm::CompletionOutcome;

/// Report an acknowledgment that named a different confirmed service.
///
/// Clauses 20.1.4.2 and 20.1.5.6 both require an acknowledgment's
/// service-ack-choice to carry "the value of the BACnetConfirmedServiceChoice
/// corresponding to the service contained in the previous
/// BACnet-Confirmed-Service-Request that has resulted in this
/// acknowledgment", so a mismatch means the peer is not answering this
/// request. The transaction stays pending; nothing else is needed here beyond
/// making the peer's misbehavior visible.
fn log_mismatch(outcome: CompletionOutcome, invoke_id: u8, pdu: &str) {
    if let CompletionOutcome::ServiceChoiceMismatch { expected, observed } = outcome {
        warn!(
            invoke_id,
            pdu,
            expected = expected.to_raw(),
            observed = observed.to_raw(),
            "Ignoring acknowledgment labelled for a different confirmed service"
        );
    }
}

async fn take_current_reassembly(
    tsm: &Arc<Mutex<Tsm>>,
    seg_state: &mut HashMap<SegKey, SegmentedReceiveState>,
    key: &SegKey,
) -> Option<SegmentedReceiveState> {
    let state = seg_state.remove(key)?;
    if tsm
        .lock()
        .await
        .owner_is_current(&key.0, key.1, &state.owner)
    {
        Some(state)
    } else {
        debug!(invoke_id = key.1, "Reclaimed stale segmented receive state");
        None
    }
}

async fn admit_terminal_response(
    tsm: &Arc<Mutex<Tsm>>,
    tsm_mac: &MacAddr,
    invoke_id: u8,
) -> TerminalResponseAdmission {
    let mut expected_owner = None;
    loop {
        let admission =
            tsm.lock()
                .await
                .admit_terminal_response(tsm_mac, invoke_id, expected_owner.as_ref());
        match admission {
            TerminalResponseAdmission::FinalSegmentSendPolling { owner, issue } => {
                issue.wait_until_polled().await;
                expected_owner = Some(owner);
            }
            admission => return admission,
        }
    }
}

impl<T: TransportPort + 'static> BACnetClient<T> {
    /// Dispatch a received APDU to the appropriate handler.
    #[allow(clippy::too_many_arguments)]
    pub(super) async fn dispatch_apdu(
        tsm: &Arc<Mutex<Tsm>>,
        device_table: &Arc<Mutex<DeviceTable>>,
        network: &Arc<NetworkLayer<T>>,
        cov_tx: &broadcast::Sender<ReceivedCOVNotification>,
        confirmed_cov_ack_policy: &ConfirmedCOVNotificationAckPolicy,
        device_tx: &broadcast::Sender<DeviceEvent>,
        seg_state: &mut HashMap<SegKey, SegmentedReceiveState>,
        seg_ack_senders: &Arc<Mutex<HashMap<SegKey, SegmentAckRoute>>>,
        source_mac: &[u8],
        source_network: &Option<NpduAddress>,
        is_group: bool,
        reply_tx: Option<oneshot::Sender<Bytes>>,
        apdu: Apdu,
        limits: ResponseLimits,
    ) {
        let tsm_mac = response_tsm_mac(source_mac, source_network);
        match apdu {
            Apdu::SimpleAck(ack) => {
                // Mid-reassembly, a SimpleACK is in Clause 5.4.4.4
                // UnexpectedPDU_Received's list, exactly like the Error and
                // Reject arms below — the segmented response under
                // reassembly IS this transaction's acknowledgment, so a
                // second one is not answering it. Checked before the TSM
                // lock: `abort_reassembly` takes that lock itself (#367).
                let key = (tsm_mac.clone(), ack.invoke_id);
                if let Some(state) = take_current_reassembly(tsm, seg_state, &key).await {
                    debug!(
                        invoke_id = ack.invoke_id,
                        "Aborting reassembly on a SimpleAck"
                    );
                    Self::abort_reassembly(
                        tsm,
                        network,
                        &tsm_mac,
                        &state.owner,
                        &state.reply_mac,
                        &state.reply_network,
                        ack.invoke_id,
                        bacnet_types::enums::AbortReason::INVALID_APDU_IN_THIS_STATE,
                    )
                    .await;
                    return;
                }
                debug!(invoke_id = ack.invoke_id, "Received SimpleAck");
                match admit_terminal_response(tsm, &tsm_mac, ack.invoke_id).await {
                    TerminalResponseAdmission::Active(owner) => {
                        let outcome = tsm.lock().await.complete_transaction_for_owner(
                            &tsm_mac,
                            ack.invoke_id,
                            &owner,
                            Some(ack.service_choice),
                            TsmResponse::SimpleAck,
                        );
                        log_mismatch(outcome, ack.invoke_id, "SimpleAck");
                    }
                    TerminalResponseAdmission::PrematureSegmentedRequestAborted => {
                        Self::send_client_abort(
                            network,
                            source_mac,
                            source_network,
                            ack.invoke_id,
                            bacnet_types::enums::AbortReason::INVALID_APDU_IN_THIS_STATE,
                        )
                        .await;
                    }
                    TerminalResponseAdmission::NoTransaction => {}
                    TerminalResponseAdmission::FinalSegmentSendPolling { .. } => unreachable!(),
                }
            }
            Apdu::ComplexAck(ack) => {
                if ack.segmented {
                    Self::handle_segmented_complex_ack(
                        tsm,
                        network,
                        seg_state,
                        source_mac,
                        source_network,
                        ack,
                        limits,
                    )
                    .await;
                } else {
                    // "BACnet-ComplexACK-PDU with 'segmented-message' =
                    // FALSE" is in the same Clause 5.4.4.4
                    // UnexpectedPDU_Received list: the transaction's answer
                    // is the segmented ComplexACK already under reassembly.
                    let key = (tsm_mac.clone(), ack.invoke_id);
                    if let Some(state) = take_current_reassembly(tsm, seg_state, &key).await {
                        debug!(
                            invoke_id = ack.invoke_id,
                            "Aborting reassembly on an unsegmented ComplexAck"
                        );
                        Self::abort_reassembly(
                            tsm,
                            network,
                            &tsm_mac,
                            &state.owner,
                            &state.reply_mac,
                            &state.reply_network,
                            ack.invoke_id,
                            bacnet_types::enums::AbortReason::INVALID_APDU_IN_THIS_STATE,
                        )
                        .await;
                        return;
                    }
                    debug!(invoke_id = ack.invoke_id, "Received ComplexAck");
                    match admit_terminal_response(tsm, &tsm_mac, ack.invoke_id).await {
                        TerminalResponseAdmission::Active(owner) => {
                            let outcome = tsm.lock().await.complete_transaction_for_owner(
                                &tsm_mac,
                                ack.invoke_id,
                                &owner,
                                Some(ack.service_choice),
                                TsmResponse::ComplexAck {
                                    service_data: ack.service_ack,
                                },
                            );
                            log_mismatch(outcome, ack.invoke_id, "ComplexAck");
                        }
                        TerminalResponseAdmission::PrematureSegmentedRequestAborted => {
                            Self::send_client_abort(
                                network,
                                source_mac,
                                source_network,
                                ack.invoke_id,
                                bacnet_types::enums::AbortReason::INVALID_APDU_IN_THIS_STATE,
                            )
                            .await;
                        }
                        TerminalResponseAdmission::NoTransaction => {}
                        TerminalResponseAdmission::FinalSegmentSendPolling { .. } => unreachable!(),
                    }
                }
            }
            Apdu::Error(err) => {
                // Mid-reassembly, an Error PDU is Clause 5.4.4.4
                // UnexpectedPDU_Received — "BACnet-Error-PDU" is in its list —
                // so the local surface is an ABORT.indication with
                // INVALID_APDU_IN_THIS_STATE, not the error content (#367).
                // Checked before the TSM lock below: `abort_reassembly` takes
                // that lock itself, and tokio's Mutex is not reentrant.
                let key = (tsm_mac.clone(), err.invoke_id);
                if let Some(state) = take_current_reassembly(tsm, seg_state, &key).await {
                    debug!(
                        invoke_id = err.invoke_id,
                        "Aborting reassembly on an Error PDU"
                    );
                    Self::abort_reassembly(
                        tsm,
                        network,
                        &tsm_mac,
                        &state.owner,
                        &state.reply_mac,
                        &state.reply_network,
                        err.invoke_id,
                        bacnet_types::enums::AbortReason::INVALID_APDU_IN_THIS_STATE,
                    )
                    .await;
                    return;
                }
                debug!(invoke_id = err.invoke_id, "Received Error PDU");
                // Correlated by invoke ID alone. Unlike 20.1.4.2 and 20.1.5.6,
                // Clause 20.1.7.2 imposes no correspondence to the requested
                // service: error-choice is "the tag value of the BACnet-Error
                // choice", and Clause 21 opens that production with
                // `other [127] Error`. Nothing in the Standard forbids a peer
                // from answering through that tag, so an exact-match gate here
                // would reject conformant responses.
                match admit_terminal_response(tsm, &tsm_mac, err.invoke_id).await {
                    TerminalResponseAdmission::Active(owner) => {
                        tsm.lock().await.complete_transaction_for_owner(
                            &tsm_mac,
                            err.invoke_id,
                            &owner,
                            None,
                            TsmResponse::Error {
                                class: err.error_class.to_raw() as u32,
                                code: err.error_code.to_raw() as u32,
                            },
                        );
                    }
                    TerminalResponseAdmission::PrematureSegmentedRequestAborted => {
                        Self::send_client_abort(
                            network,
                            source_mac,
                            source_network,
                            err.invoke_id,
                            bacnet_types::enums::AbortReason::INVALID_APDU_IN_THIS_STATE,
                        )
                        .await;
                    }
                    TerminalResponseAdmission::NoTransaction => {}
                    TerminalResponseAdmission::FinalSegmentSendPolling { .. } => unreachable!(),
                }
            }
            Apdu::Reject(rej) => {
                // Same Clause 5.4.4.4 UnexpectedPDU_Received diversion as the
                // Error arm above ("BACnet-Reject-PDU" is in the same list),
                // with the same lock-ordering constraint (#367).
                let key = (tsm_mac.clone(), rej.invoke_id);
                if let Some(state) = take_current_reassembly(tsm, seg_state, &key).await {
                    debug!(
                        invoke_id = rej.invoke_id,
                        "Aborting reassembly on a Reject PDU"
                    );
                    Self::abort_reassembly(
                        tsm,
                        network,
                        &tsm_mac,
                        &state.owner,
                        &state.reply_mac,
                        &state.reply_network,
                        rej.invoke_id,
                        bacnet_types::enums::AbortReason::INVALID_APDU_IN_THIS_STATE,
                    )
                    .await;
                    return;
                }
                debug!(invoke_id = rej.invoke_id, "Received Reject PDU");
                let mut tsm = tsm.lock().await;
                // Carries no service choice (Clause 20.1.8); invoke ID is the
                // only correlation the Standard provides.
                tsm.complete_transaction(
                    &tsm_mac,
                    rej.invoke_id,
                    None,
                    TsmResponse::Reject {
                        reason: rej.reject_reason.to_raw(),
                    },
                );
            }
            Apdu::Abort(abt) => {
                // Clause 5.4.4.3 AbortPDU_Received fires only for an Abort
                // "whose 'server' parameter is TRUE". An Abort this client
                // itself sent — 5.4.4.4 emits them with 'server' = FALSE —
                // must not, echoed back or spoofed, complete the very
                // transaction it was trying to abort.
                if !abt.sent_by_server {
                    debug!(
                        invoke_id = abt.invoke_id,
                        "Ignoring Abort PDU with server=FALSE"
                    );
                    return;
                }
                // Clause 5.4.4.4 AbortPDU_Received: "send ABORT.indication to
                // the local application program; and enter the IDLE state" —
                // ending the reassembly session is the IDLE half, and no
                // reply PDU is prescribed (#367). This removal must stay
                // below the server=FALSE guard above, or an echoed copy of
                // this client's own Abort would tear down a healthy
                // reassembly. Behaviorally redundant with the per-segment
                // pending gate in `handle_segmented_complex_ack` — a later
                // segment would find no transaction and clear the session
                // anyway — so no test can pin this line alone; it is kept so
                // the slot frees at the Abort, not at the peer's next move.
                let key = (tsm_mac.clone(), abt.invoke_id);
                let state = take_current_reassembly(tsm, seg_state, &key).await;
                debug!(invoke_id = abt.invoke_id, "Received Abort PDU");
                let mut tsm = tsm.lock().await;
                // Carries no service choice (Clause 20.1.9).
                let response = TsmResponse::Abort {
                    reason: abt.abort_reason.to_raw(),
                };
                if let Some(state) = state {
                    tsm.complete_transaction_for_owner(
                        &tsm_mac,
                        abt.invoke_id,
                        &state.owner,
                        None,
                        response,
                    );
                } else {
                    tsm.complete_transaction(&tsm_mac, abt.invoke_id, None, response);
                }
            }
            Apdu::ConfirmedRequest(req) => {
                if is_group {
                    debug!(
                        invoke_id = req.invoke_id,
                        service = req.service_choice.to_raw(),
                        "Ignoring group-addressed ConfirmedRequest"
                    );
                    return;
                }
                if req.segmented {
                    Self::send_server_abort(
                        network,
                        source_mac,
                        source_network,
                        reply_tx,
                        req.invoke_id,
                        bacnet_types::enums::AbortReason::SEGMENTATION_NOT_SUPPORTED,
                    )
                    .await;
                    return;
                }
                if req.service_choice == ConfirmedServiceChoice::CONFIRMED_COV_NOTIFICATION {
                    match COVNotificationRequest::decode_detailed(&req.service_request) {
                        Ok(notification) => {
                            debug!(
                                object = ?notification.monitored_object_identifier,
                                "Received ConfirmedCOVNotification"
                            );
                            let received = ReceivedCOVNotification::new(
                                notification,
                                source_mac,
                                source_network,
                                COVNotificationDelivery::Confirmed,
                            );
                            let response = confirmed_cov_ack_policy(&received);
                            let _ = cov_tx.send(received);
                            Self::send_confirmed_cov_notification_response(
                                network,
                                source_mac,
                                source_network,
                                req.invoke_id,
                                req.service_choice,
                                response,
                                reply_tx,
                            )
                            .await;
                        }
                        Err(e) => {
                            let reject_reason = e.reject_reason();
                            let e = e.into_error();
                            warn!(error = %e, "Failed to decode ConfirmedCOVNotification");
                            Self::send_confirmed_request_reject(
                                network,
                                source_mac,
                                source_network,
                                reply_tx,
                                req.invoke_id,
                                reject_reason,
                            )
                            .await;
                        }
                    }
                } else {
                    debug!(
                        service = req.service_choice.to_raw(),
                        "Rejecting unsupported ConfirmedRequest (client mode)"
                    );
                    Self::send_confirmed_request_reject(
                        network,
                        source_mac,
                        source_network,
                        reply_tx,
                        req.invoke_id,
                        RejectReason::UNRECOGNIZED_SERVICE,
                    )
                    .await;
                }
            }
            Apdu::UnconfirmedRequest(req) => {
                if req.service_choice == UnconfirmedServiceChoice::I_AM {
                    match bacnet_services::who_is::IAmRequest::decode(&req.service_request) {
                        Ok(i_am) => {
                            debug!(
                                device = i_am.object_identifier.instance_number(),
                                vendor = i_am.vendor_id,
                                "Received IAm"
                            );
                            let (src_net, src_addr) = match source_network {
                                Some(npdu_addr) if !npdu_addr.mac_address.is_empty() => {
                                    (Some(npdu_addr.network), Some(npdu_addr.mac_address.clone()))
                                }
                                _ => (None, None),
                            };
                            let device = DiscoveredDevice {
                                object_identifier: i_am.object_identifier,
                                mac_address: MacAddr::from_slice(source_mac),
                                max_apdu_length: i_am.max_apdu_length,
                                segmentation_supported: i_am.segmentation_supported,
                                max_segments_accepted: None,
                                vendor_id: i_am.vendor_id,
                                last_seen: std::time::Instant::now(),
                                source_network: src_net,
                                source_address: src_addr,
                            };
                            let status =
                                device_table.lock().await.upsert_with_result(device.clone());
                            let kind = match status {
                                DeviceUpsertResult::Inserted => Some(DeviceEventKind::Discovered),
                                DeviceUpsertResult::Updated => Some(DeviceEventKind::Updated),
                                DeviceUpsertResult::Dropped => None,
                            };
                            if let Some(kind) = kind {
                                let _ = device_tx.send(DeviceEvent { kind, device });
                            }
                        }
                        Err(e) => {
                            warn!(error = %e, "Failed to decode IAm");
                        }
                    }
                } else if req.service_choice
                    == UnconfirmedServiceChoice::UNCONFIRMED_COV_NOTIFICATION
                {
                    match COVNotificationRequest::decode(&req.service_request) {
                        Ok(notification) => {
                            debug!(
                                object = ?notification.monitored_object_identifier,
                                "Received UnconfirmedCOVNotification"
                            );
                            let received = ReceivedCOVNotification::new(
                                notification,
                                source_mac,
                                source_network,
                                COVNotificationDelivery::Unconfirmed,
                            );
                            let _ = cov_tx.send(received);
                        }
                        Err(e) => {
                            warn!(error = %e, "Failed to decode UnconfirmedCOVNotification");
                        }
                    }
                } else {
                    debug!(
                        service = req.service_choice.to_raw(),
                        "Ignoring unconfirmed service in client dispatch"
                    );
                }
            }
            Apdu::SegmentAck(sa) => {
                // Clause 5.4.4.2 gates DuplicateACK_Received, NewACK_Received
                // and FinalACK_Received on the 'server' parameter being TRUE.
                // A SegmentACK this client sent while receiving a segmented
                // response carries server=FALSE and must not be fed back into
                // its own segmented send.
                //
                // This check must stay ahead of the Abort below. A client
                // emits SegmentACKs with 'server' = FALSE, so if the order
                // were reversed, two of these clients exchanging a segmented
                // ConfirmedCOVNotification would answer each other's
                // SegmentACKs with Aborts indefinitely. Dropping them here is
                // what keeps the Abort reachable only by a *server's* PDU.
                if !sa.sent_by_server {
                    debug!(
                        invoke_id = sa.invoke_id,
                        "Ignoring SegmentAck with server=FALSE"
                    );
                    return;
                }
                let invoke_id = sa.invoke_id;
                let key = (tsm_mac.clone(), invoke_id);

                // SEGMENTED_CONF (5.4.4.4) `UnexpectedPDU_Received` lists
                // "BACnet-SegmentACK-PDU with 'server' = TRUE" among the PDUs
                // that do not belong in this state, and requires all three of:
                // "transmit a BACnet-Abort-PDU with 'server' = FALSE; send
                // ABORT.indication with 'server' = FALSE and 'abort-reason' =
                // INVALID_APDU_IN_THIS_STATE to the local application program;
                // and enter the IDLE state."
                //
                // Receive state is checked before the outgoing phase because
                // SEGMENTED_CONF gives this PDU the opposite disposition.
                if let Some(state) = take_current_reassembly(tsm, seg_state, &key).await {
                    debug!(invoke_id, "Aborting reassembly on an unexpected SegmentAck");
                    // The stored identity, not this PDU's source. A key match
                    // already forces the inbound SNET/SADR to equal the
                    // stored pair (the key is derived from it), but the
                    // immediate MAC can diverge — a second router to the same
                    // peer — and reading both from the state keeps the
                    // (reply_mac, reply_network) pair consistent.
                    Self::abort_reassembly(
                        tsm,
                        network,
                        &tsm_mac,
                        &state.owner,
                        &state.reply_mac,
                        &state.reply_network,
                        invoke_id,
                        bacnet_types::enums::AbortReason::INVALID_APDU_IN_THIS_STATE,
                    )
                    .await;
                    return;
                }

                // Hold the TSM lock through the route lookup and try_send.
                // Terminal completion uses this same lock, so a raw sender
                // entry cannot outlive the authoritative phase for delivery.
                let tsm_guard = tsm.lock().await;
                match tsm_guard.segment_ack_phase(&tsm_mac, invoke_id) {
                    SegmentAckPhase::SegmentedRequest(owner) => {
                        // Lock order is TSM then SegmentACK routes. Setup and
                        // cleanup never hold both locks.
                        let senders = seg_ack_senders.lock().await;
                        if let Some(route) = senders
                            .get(&key)
                            .filter(|route| route.owner.same_as(&owner))
                        {
                            let _ = route.sender.try_send(sa);
                        }
                        return;
                    }
                    SegmentAckPhase::Outstanding => {
                        debug!(
                            invoke_id,
                            "Discarding duplicate SegmentAck for an outstanding transaction"
                        );
                        return;
                    }
                    SegmentAckPhase::Idle => {}
                }
                drop(tsm_guard);

                // IDLE (5.4.4.1) `UnexpectedSegmentInfoReceived`: nothing is
                // outstanding, so a server SegmentACK earns a client Abort.
                debug!(invoke_id, "Aborting SegmentAck received while idle");
                Self::send_client_abort(
                    network,
                    source_mac,
                    source_network,
                    invoke_id,
                    bacnet_types::enums::AbortReason::INVALID_APDU_IN_THIS_STATE,
                )
                .await;
            }
        }
    }

    async fn send_confirmed_request_reject(
        network: &Arc<NetworkLayer<T>>,
        source_mac: &[u8],
        source_network: &Option<NpduAddress>,
        reply_tx: Option<oneshot::Sender<Bytes>>,
        invoke_id: u8,
        reject_reason: RejectReason,
    ) {
        let reject = Apdu::Reject(RejectPdu {
            invoke_id,
            reject_reason,
        });
        let mut buf = BytesMut::with_capacity(3);
        if let Err(e) = encode_apdu(&mut buf, &reject) {
            warn!(error = %e, reason = reject_reason.to_raw(), "Failed to encode Reject");
            return;
        }
        if let Err(e) =
            Self::send_received_reply_apdu(network, &buf, source_mac, source_network, reply_tx)
                .await
        {
            warn!(error = %e, reason = reject_reason.to_raw(), "Failed to send Reject");
        }
    }

    async fn send_server_abort(
        network: &Arc<NetworkLayer<T>>,
        source_mac: &[u8],
        source_network: &Option<NpduAddress>,
        reply_tx: Option<oneshot::Sender<Bytes>>,
        invoke_id: u8,
        abort_reason: bacnet_types::enums::AbortReason,
    ) {
        let abort = Apdu::Abort(AbortPdu {
            sent_by_server: true,
            invoke_id,
            abort_reason,
        });
        let mut buf = BytesMut::with_capacity(3);
        if let Err(e) = encode_apdu(&mut buf, &abort) {
            warn!(error = %e, reason = abort_reason.to_raw(), "Failed to encode server Abort");
            return;
        }
        if let Err(e) =
            Self::send_received_reply_apdu(network, &buf, source_mac, source_network, reply_tx)
                .await
        {
            warn!(error = %e, reason = abort_reason.to_raw(), "Failed to send server Abort");
        }
    }

    async fn send_confirmed_cov_notification_response(
        network: &Arc<NetworkLayer<T>>,
        source_mac: &[u8],
        source_network: &Option<NpduAddress>,
        invoke_id: u8,
        service_choice: ConfirmedServiceChoice,
        response: ConfirmedCOVNotificationResponse,
        reply_tx: Option<oneshot::Sender<Bytes>>,
    ) {
        let apdu = match response {
            ConfirmedCOVNotificationResponse::Ack => Apdu::SimpleAck(SimpleAck {
                invoke_id,
                service_choice,
            }),
            ConfirmedCOVNotificationResponse::Reject(reject_reason) => Apdu::Reject(RejectPdu {
                invoke_id,
                reject_reason,
            }),
            ConfirmedCOVNotificationResponse::NoResponse => return,
        };

        let mut buf = BytesMut::with_capacity(4);
        if let Err(e) = encode_apdu(&mut buf, &apdu) {
            warn!(error = %e, "Failed to encode response for COV notification");
            return;
        }
        if let Err(e) =
            Self::send_received_reply_apdu(network, &buf, source_mac, source_network, reply_tx)
                .await
        {
            warn!(error = %e, "Failed to send response for COV notification");
        }
    }

    async fn send_received_reply_apdu(
        network: &Arc<NetworkLayer<T>>,
        buf: &[u8],
        reply_mac: &[u8],
        reply_network: &Option<NpduAddress>,
        reply_tx: Option<oneshot::Sender<Bytes>>,
    ) -> Result<(), Error> {
        if let Some(reply_tx) = reply_tx {
            let apdu = Bytes::copy_from_slice(buf);
            let mut npdu_buf = BytesMut::with_capacity(8 + apdu.len());
            encode_npdu(
                &mut npdu_buf,
                &Npdu {
                    is_network_message: false,
                    expecting_reply: false,
                    priority: NetworkPriority::NORMAL,
                    destination: reply_network
                        .clone()
                        .filter(|address| !address.mac_address.is_empty()),
                    source: None,
                    payload: apdu,
                    ..Npdu::default()
                },
            )?;
            if reply_tx.send(npdu_buf.freeze()).is_ok() {
                return Ok(());
            }
        }

        Self::send_reply_apdu(network, buf, reply_mac, reply_network).await
    }

    /// Send a reply back along the path its trigger arrived on.
    ///
    /// A PDU from a routed peer carries the peer's SNET/SADR; the reply must
    /// carry that pair as DNET/DADR, unicast to the router that delivered the
    /// original, or the router treats it as locally addressed and never
    /// forwards it. Every PDU answering an inbound one goes through here so
    /// no reply site can drop the routing half of the address again.
    pub(super) async fn send_reply_apdu(
        network: &Arc<NetworkLayer<T>>,
        buf: &[u8],
        reply_mac: &[u8],
        reply_network: &Option<NpduAddress>,
    ) -> Result<(), Error> {
        match reply_network {
            Some(address) if !address.mac_address.is_empty() => {
                network
                    .send_apdu_routed(
                        buf,
                        address.network,
                        &address.mac_address,
                        reply_mac,
                        false,
                        NetworkPriority::NORMAL,
                    )
                    .await
            }
            _ => {
                network
                    .send_apdu(buf, reply_mac, false, NetworkPriority::NORMAL)
                    .await
            }
        }
    }
}
