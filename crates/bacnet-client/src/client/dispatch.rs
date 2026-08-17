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
        seg_ack_senders: &Arc<Mutex<HashMap<SegKey, mpsc::Sender<SegmentAckPdu>>>>,
        source_mac: &[u8],
        source_network: &Option<NpduAddress>,
        apdu: Apdu,
        limits: ResponseLimits,
    ) {
        let tsm_mac = response_tsm_mac(source_mac, source_network);
        match apdu {
            Apdu::SimpleAck(ack) => {
                debug!(invoke_id = ack.invoke_id, "Received SimpleAck");
                let mut tsm = tsm.lock().await;
                let outcome = tsm.complete_transaction(
                    &tsm_mac,
                    ack.invoke_id,
                    Some(ack.service_choice),
                    TsmResponse::SimpleAck,
                );
                log_mismatch(outcome, ack.invoke_id, "SimpleAck");
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
                    debug!(invoke_id = ack.invoke_id, "Received ComplexAck");
                    let mut tsm = tsm.lock().await;
                    let outcome = tsm.complete_transaction(
                        &tsm_mac,
                        ack.invoke_id,
                        Some(ack.service_choice),
                        TsmResponse::ComplexAck {
                            service_data: ack.service_ack,
                        },
                    );
                    log_mismatch(outcome, ack.invoke_id, "ComplexAck");
                }
            }
            Apdu::Error(err) => {
                debug!(invoke_id = err.invoke_id, "Received Error PDU");
                let mut tsm = tsm.lock().await;
                // Correlated by invoke ID alone. Clause 20.1.7.2 words the
                // Error PDU's service choice differently from the ACK clauses
                // — "the tag value of the BACnet-Error choice" — and Clause 21
                // defines `BACnet-Error ::= CHOICE { other [127] Error, ... }`,
                // so a conformant peer may answer any service with choice 127.
                // Requiring an exact match would reject those.
                tsm.complete_transaction(
                    &tsm_mac,
                    err.invoke_id,
                    None,
                    TsmResponse::Error {
                        class: err.error_class.to_raw() as u32,
                        code: err.error_code.to_raw() as u32,
                    },
                );
            }
            Apdu::Reject(rej) => {
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
                debug!(invoke_id = abt.invoke_id, "Received Abort PDU");
                let mut tsm = tsm.lock().await;
                // Carries no service choice (Clause 20.1.9).
                tsm.complete_transaction(
                    &tsm_mac,
                    abt.invoke_id,
                    None,
                    TsmResponse::Abort {
                        reason: abt.abort_reason.to_raw(),
                    },
                );
            }
            Apdu::ConfirmedRequest(req) => {
                if req.service_choice == ConfirmedServiceChoice::CONFIRMED_COV_NOTIFICATION {
                    match COVNotificationRequest::decode(&req.service_request) {
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
                            )
                            .await;
                        }
                        Err(e) => {
                            warn!(error = %e, "Failed to decode ConfirmedCOVNotification");
                        }
                    }
                } else {
                    debug!(
                        service = req.service_choice.to_raw(),
                        "Ignoring ConfirmedRequest (client mode)"
                    );
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
                if !sa.sent_by_server {
                    debug!(
                        invoke_id = sa.invoke_id,
                        "Ignoring SegmentAck with server=FALSE"
                    );
                    return;
                }
                let key = (tsm_mac, sa.invoke_id);
                let senders = seg_ack_senders.lock().await;
                if let Some(tx) = senders.get(&key) {
                    let _ = tx.try_send(sa);
                } else {
                    debug!(
                        invoke_id = sa.invoke_id,
                        "Ignoring SegmentAck for unknown transaction"
                    );
                }
            }
        }
    }

    async fn send_confirmed_cov_notification_response(
        network: &Arc<NetworkLayer<T>>,
        source_mac: &[u8],
        source_network: &Option<NpduAddress>,
        invoke_id: u8,
        service_choice: ConfirmedServiceChoice,
        response: ConfirmedCOVNotificationResponse,
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
        let send_result = match source_network {
            Some(address) if !address.mac_address.is_empty() => {
                network
                    .send_apdu_routed(
                        &buf,
                        address.network,
                        &address.mac_address,
                        source_mac,
                        false,
                        NetworkPriority::NORMAL,
                    )
                    .await
            }
            _ => {
                network
                    .send_apdu(&buf, source_mac, false, NetworkPriority::NORMAL)
                    .await
            }
        };
        if let Err(e) = send_result {
            warn!(error = %e, "Failed to send response for COV notification");
        }
    }
}
