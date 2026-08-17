use super::*;
use crate::tsm::CompletionOutcome;
use bacnet_encoding::apdu::advertised_max_segments;

/// Size of the sequence-number space, and so the hard reassembly ceiling.
///
/// A local storage bound, not a protocol one. Clause 20.1.5.4 makes the
/// sequence number modulo 256, so a longer response is entirely representable —
/// this client simply keys its segment store by that `u8` and cannot tell
/// segment 257 from segment 1. Clause 5.4.4.4 names this exact situation
/// (`NewSegmentReceived_NoSpace`, "the segment cannot be saved due to local
/// conditions") and prescribes the Abort below.
///
/// Exactly 256 segments reassemble correctly and must keep working; 257 is the
/// first that would corrupt the payload.
const SEQUENCE_NUMBER_SPACE: usize = 256;

impl ResponseLimits {
    /// The receive-side limits `config` puts on the wire.
    pub(super) fn from_config(config: &ClientConfig) -> Self {
        // Clause 20.1.2.4 defines max-segments-accepted as "the maximum number
        // of segments that the device will accept"; Clause 5.2.1.3 makes it
        // binding, requiring the segment count to be the smallest of the
        // sender's own limit and "(b) the maximum number of segments accepted
        // by the remote peer device" — which, for a ComplexACK, is "the 'Max
        // Segments Accepted' parameter of the BACnet-Confirmed-Request-PDU for
        // which this is a response". A peer that overruns it is therefore
        // non-conformant, not merely unusual.
        //
        // Only the rungs B'001'..B'110' name a number; B'000' and B'111'
        // promise nothing, and `advertised_max_segments` reports those as
        // `None`.
        let advertised =
            advertised_max_segments(config.max_segments).map_or(usize::MAX, usize::from);
        Self {
            segmented_response_accepted: config.segmented_response_accepted,
            max_reassembly_segments: advertised.min(SEQUENCE_NUMBER_SPACE),
        }
    }
}

impl<T: TransportPort + 'static> BACnetClient<T> {
    /// Transmit an Abort this client originates.
    ///
    /// Every Abort a requesting BACnet-user sends carries `'server' = FALSE` —
    /// Clauses 5.4.4.1, 5.4.4.3 and 5.4.4.4 each spell it out — because the
    /// flag names the sender's role, not the error.
    pub(super) async fn send_client_abort(
        network: &Arc<NetworkLayer<T>>,
        reply_mac: &[u8],
        reply_network: &Option<NpduAddress>,
        invoke_id: u8,
        abort_reason: bacnet_types::enums::AbortReason,
    ) {
        let abort = Apdu::Abort(AbortPdu {
            sent_by_server: false,
            invoke_id,
            abort_reason,
        });
        let mut buf = BytesMut::with_capacity(4);
        if let Err(e) = encode_apdu(&mut buf, &abort) {
            warn!(error = %e, reason = abort_reason.to_raw(), "Failed to encode Abort");
            return;
        }
        if let Err(e) = Self::send_reply_apdu(network, &buf, reply_mac, reply_network).await {
            warn!(error = %e, reason = abort_reason.to_raw(), "Failed to send Abort");
        }
    }

    /// Abort a reassembly in progress, telling both the peer and the caller.
    ///
    /// Clause 5.4.4.4 gives this same shape to every way SEGMENTED_CONF can
    /// end badly — `NewSegmentReceived_NoSpace` for a segment that "cannot be
    /// saved due to local conditions" and `UnexpectedPDU_Received` for a PDU
    /// that does not belong in the state. Both "transmit a BACnet-Abort-PDU
    /// with 'server' = FALSE", "send ABORT.indication ... to the local
    /// application program", and "enter the IDLE state"; only `abort-reason`
    /// differs. The local ABORT.indication is the waiting caller, so the
    /// transaction is completed rather than left to time out.
    ///
    /// The caller is responsible for having removed the `seg_state` entry —
    /// that is the "enter the IDLE state" half.
    pub(super) async fn abort_reassembly(
        tsm: &Arc<Mutex<Tsm>>,
        network: &Arc<NetworkLayer<T>>,
        tsm_mac: &MacAddr,
        reply_mac: &MacAddr,
        reply_network: &Option<NpduAddress>,
        invoke_id: u8,
        reason: bacnet_types::enums::AbortReason,
    ) {
        Self::send_client_abort(network, reply_mac, reply_network, invoke_id, reason).await;
        tsm.lock().await.complete_transaction(
            tsm_mac,
            invoke_id,
            None,
            TsmResponse::Abort {
                reason: reason.to_raw(),
            },
        );
    }

    /// Handle a segmented ComplexAck: accumulate segments, send SegmentAcks,
    /// and reassemble when all segments are received.
    pub(super) async fn handle_segmented_complex_ack(
        tsm: &Arc<Mutex<Tsm>>,
        network: &Arc<NetworkLayer<T>>,
        seg_state: &mut HashMap<SegKey, SegmentedReceiveState>,
        source_mac: &[u8],
        source_network: &Option<NpduAddress>,
        ack: bacnet_encoding::apdu::ComplexAck,
        limits: ResponseLimits,
    ) {
        let seq = ack.sequence_number.unwrap_or(0);
        let tsm_mac = response_tsm_mac(source_mac, source_network);
        let key = (tsm_mac.clone(), ack.invoke_id);

        debug!(
            invoke_id = ack.invoke_id,
            seq = seq,
            more = ack.more_follows,
            "Received segmented ComplexAck"
        );

        // A segmented ComplexACK when this device does not support
        // segmentation is Clause 5.4.4.3's UnexpectedPDU_Received, which
        // requires an Abort with 'server' = FALSE. The transmitted reason
        // follows Clause 18.10, which names SEGMENTATION_NOT_SUPPORTED for
        // exactly this case.
        if !limits.segmented_response_accepted {
            let abort = Apdu::Abort(AbortPdu {
                sent_by_server: false,
                invoke_id: ack.invoke_id,
                abort_reason: bacnet_types::enums::AbortReason::SEGMENTATION_NOT_SUPPORTED,
            });
            let mut buf = BytesMut::with_capacity(4);
            if let Err(e) = encode_apdu(&mut buf, &abort) {
                warn!(error = %e, "Failed to encode segmentation-not-supported Abort");
                return;
            }
            let _ = Self::send_reply_apdu(network, &buf, source_mac, source_network).await;
            return;
        }

        const MAX_CONCURRENT_SEG_SESSIONS: usize = 64;
        if !seg_state.contains_key(&key) && seg_state.len() >= MAX_CONCURRENT_SEG_SESSIONS {
            warn!(
                invoke_id = ack.invoke_id,
                sessions = seg_state.len(),
                "Max concurrent segmented sessions reached, dropping segment"
            );
            return;
        }

        // Only a request this client actually issued may open a reassembly
        // session. Without this, an unsolicited peer can occupy all 64 slots
        // with invoke IDs nobody is waiting on and starve real responses until
        // the reaper runs. Clause 5.4.4.1's IDLE state has no transition into
        // SEGMENTED_CONF: it is entered only from SEGMENTED_REQUEST (5.4.4.2)
        // or AWAIT_CONFIRMATION (5.4.4.3), both of which mean this device has
        // a request outstanding.
        //
        // Bind the guard so its scope is obvious: it must not be held across
        // the send below, and an `if let` here would extend it silently.
        let transaction_pending = {
            seg_state.contains_key(&key)
                || tsm
                    .lock()
                    .await
                    .expected_service_choice(&tsm_mac, ack.invoke_id)
                    .is_some()
        };
        if !transaction_pending {
            // Clause 5.4.4.1 UnexpectedSegmentInfoReceived names this exact
            // PDU — "an unexpected PDU indicating the existence of an active
            // server TSM (BACnet-ComplexACK-PDU with 'segmented-message' =
            // TRUE ...)" — and prescribes an answer, not silence: "transmit a
            // BACnet-Abort-PDU with 'server' = FALSE and 'abort-reason' =
            // INVALID_APDU_IN_THIS_STATE and enter the IDLE state."
            debug!(
                invoke_id = ack.invoke_id,
                "Aborting segmented ComplexAck for a transaction that is not pending"
            );
            Self::send_client_abort(
                network,
                source_mac,
                source_network,
                ack.invoke_id,
                bacnet_types::enums::AbortReason::INVALID_APDU_IN_THIS_STATE,
            )
            .await;
            return;
        }

        let proposed_ws = ack.proposed_window_size.unwrap_or(1);
        let state = seg_state
            .entry(key.clone())
            .or_insert_with(|| SegmentedReceiveState {
                receiver: SegmentReceiver::new(),
                reply_mac: MacAddr::from_slice(source_mac),
                reply_network: source_network.clone(),
                expected_next_seq: 0,
                last_activity: Instant::now(),
                window_position: 0,
                proposed_window_size: proposed_ws,
                accepted_segments: 0,
            });

        state.last_activity = Instant::now();

        if seq != state.expected_next_seq {
            // Check for duplicate (already received) vs true gap
            if seq < state.expected_next_seq {
                // Duplicate segment — discard silently and ack
                debug!(
                    invoke_id = ack.invoke_id,
                    seq, "Discarding duplicate segment"
                );
            } else {
                // True gap — send negative SegmentAck with last correctly received seq
                warn!(
                    invoke_id = ack.invoke_id,
                    expected = state.expected_next_seq,
                    received = seq,
                    "Segment gap detected, sending negative SegmentAck"
                );
            }
            let neg_ack = Apdu::SegmentAck(SegmentAckPdu {
                negative_ack: seq >= state.expected_next_seq,
                sent_by_server: false,
                invoke_id: ack.invoke_id,
                // Spec: sequence_number = last correctly received sequence number
                sequence_number: if state.expected_next_seq > 0 {
                    state.expected_next_seq.wrapping_sub(1)
                } else {
                    0
                },
                actual_window_size: proposed_ws,
            });
            let mut buf = BytesMut::with_capacity(4);
            if let Err(e) = encode_apdu(&mut buf, &neg_ack) {
                warn!(error = %e, "Failed to encode negative SegmentAck");
                return;
            }
            if let Err(e) = Self::send_reply_apdu(network, &buf, source_mac, source_network).await {
                warn!(error = %e, "Failed to send SegmentAck");
            }
            return;
        }

        // Reached only by an in-order NEW segment: every duplicate and every
        // out-of-order segment returned above. That placement is the whole
        // point — Clause 5.4.4.4 requires a duplicate to be discarded, not
        // treated as an error, so a cap that duplicates could trip would abort
        // healthy transfers on retransmission.
        if state.accepted_segments >= limits.max_reassembly_segments {
            warn!(
                invoke_id = ack.invoke_id,
                accepted = state.accepted_segments,
                limit = limits.max_reassembly_segments,
                "Segmented response exceeds reassembly capacity, aborting"
            );
            let reply_mac = state.reply_mac.clone();
            let reply_network = state.reply_network.clone();
            seg_state.remove(&key);
            Self::abort_reassembly(
                tsm,
                network,
                &tsm_mac,
                &reply_mac,
                &reply_network,
                ack.invoke_id,
                bacnet_types::enums::AbortReason::BUFFER_OVERFLOW,
            )
            .await;
            return;
        }

        if let Err(e) = state.receiver.receive(seq, ack.service_ack) {
            // Also "the segment cannot be saved due to local conditions", so
            // Clause 5.4.4.4 wants the same Abort rather than leaving the
            // caller to time out on a session that can no longer complete.
            warn!(error = %e, "Rejecting oversized segment");
            let reply_mac = state.reply_mac.clone();
            let reply_network = state.reply_network.clone();
            seg_state.remove(&key);
            Self::abort_reassembly(
                tsm,
                network,
                &tsm_mac,
                &reply_mac,
                &reply_network,
                ack.invoke_id,
                bacnet_types::enums::AbortReason::BUFFER_OVERFLOW,
            )
            .await;
            return;
        }
        state.accepted_segments += 1;
        state.expected_next_seq = seq.wrapping_add(1);
        state.window_position += 1;

        // Per-window SegmentAck: only ack at window boundary or final segment (Clause 5.2.2)
        let should_ack = !ack.more_follows || state.window_position >= state.proposed_window_size;

        if should_ack {
            state.window_position = 0;
            let seg_ack = Apdu::SegmentAck(SegmentAckPdu {
                negative_ack: false,
                sent_by_server: false,
                invoke_id: ack.invoke_id,
                sequence_number: seq,
                actual_window_size: proposed_ws,
            });
            let mut buf = BytesMut::with_capacity(4);
            if let Err(e) = encode_apdu(&mut buf, &seg_ack) {
                warn!(error = %e, "Failed to encode SegmentAck");
                return;
            }
            if let Err(e) = Self::send_reply_apdu(network, &buf, source_mac, source_network).await {
                warn!(error = %e, "Failed to send SegmentAck");
            }
        }

        if !ack.more_follows {
            let state = seg_state.remove(&key).unwrap();
            let total = state.receiver.received_count();
            match state.receiver.reassemble(total) {
                Ok(service_data) => {
                    debug!(
                        invoke_id = ack.invoke_id,
                        segments = total,
                        bytes = service_data.len(),
                        "Reassembled segmented ComplexAck"
                    );
                    let mut tsm = tsm.lock().await;
                    let outcome = tsm.complete_transaction(
                        &tsm_mac,
                        ack.invoke_id,
                        Some(ack.service_choice),
                        TsmResponse::ComplexAck {
                            service_data: Bytes::from(service_data),
                        },
                    );
                    if let CompletionOutcome::ServiceChoiceMismatch { expected, observed } = outcome
                    {
                        warn!(
                            invoke_id = ack.invoke_id,
                            expected = expected.to_raw(),
                            observed = observed.to_raw(),
                            "Discarding reassembled ComplexAck labelled for a different service"
                        );
                    }
                }
                Err(e) => {
                    warn!(error = %e, "Failed to reassemble segmented ComplexAck");
                }
            }
        }
    }
    /// Send a confirmed request using segmented transfer with windowed flow control.
    pub(super) async fn segmented_confirmed_request(
        &self,
        target: ConfirmedTarget<'_>,
        service_choice: ConfirmedServiceChoice,
        service_data: &[u8],
        remote_max_apdu: u16,
        remote_max_segments: Option<u32>,
    ) -> Result<Bytes, Error> {
        let tsm_mac = target.tsm_mac();
        let advertised_max_apdu = self.advertised_max_apdu_length_for_target(target)?;
        let max_seg_size = max_segment_payload(remote_max_apdu, SegmentedPduType::ConfirmedRequest);
        let segments = split_payload(service_data, max_seg_size)?;
        let total_segments = segments.len();

        if let Some(max_seg) = remote_max_segments {
            if total_segments > max_seg as usize {
                return Err(Error::Segmentation(format!(
                    "request requires {} segments but remote accepts at most {}",
                    total_segments, max_seg
                )));
            }
        }

        debug!(
            total_segments,
            max_seg_size,
            service_data_len = service_data.len(),
            "Starting segmented confirmed request"
        );

        let (invoke_id, rx) = {
            let mut tsm = self.tsm.lock().await;
            let invoke_id = tsm.allocate_invoke_id(&tsm_mac).ok_or_else(|| {
                Error::Encoding("all invoke IDs exhausted for destination".into())
            })?;
            let rx = tsm.register_transaction(tsm_mac.clone(), invoke_id, service_choice);
            (invoke_id, rx)
        };

        let (seg_ack_tx, mut seg_ack_rx) = mpsc::channel(16);
        {
            let key = (tsm_mac.clone(), invoke_id);
            self.seg_ack_senders.lock().await.insert(key, seg_ack_tx);
        }

        // Tseg: use APDU timeout for now (configurable via apdu_timeout_ms)
        let timeout_duration = Duration::from_millis(self.config.apdu_timeout_ms);
        let max_ack_retries = self.config.apdu_retries;
        let mut window_size = self.config.proposed_window_size.max(1) as usize;
        let mut next_seq: usize = 0;
        let mut neg_ack_retries: u32 = 0;
        const MAX_NEG_ACK_RETRIES: u32 = 10;

        let result = async {
            while next_seq < total_segments {
                let window_start = next_seq;
                let window_end = (window_start + window_size).min(total_segments);

                for (seq, segment_data) in segments[window_start..window_end]
                    .iter()
                    .enumerate()
                    .map(|(i, s)| (window_start + i, s))
                {
                    let is_last = seq == total_segments - 1;
                    let pdu = Apdu::ConfirmedRequest(ConfirmedRequestPdu {
                        segmented: true,
                        more_follows: !is_last,
                        segmented_response_accepted: self.config.segmented_response_accepted,
                        max_segments: self.config.max_segments,
                        max_apdu_length: advertised_max_apdu,
                        invoke_id,
                        sequence_number: Some(seq as u8),
                        proposed_window_size: Some(self.config.proposed_window_size.max(1)),
                        service_choice,
                        service_request: segment_data.clone(),
                    });

                    let mut buf = BytesMut::with_capacity(remote_max_apdu as usize);
                    encode_apdu(&mut buf, &pdu)?;

                    self.send_confirmed_target_apdu(target, &buf).await?;

                    debug!(seq, is_last, "Sent segment");
                }

                let ack = {
                    let mut ack_retries: u8 = 0;
                    loop {
                        match timeout(timeout_duration, seg_ack_rx.recv()).await {
                            Ok(Some(ack)) => {
                                let ack_seq = ack.sequence_number as usize;
                                if ack_seq >= total_segments {
                                    return Err(Error::Segmentation(format!(
                                        "SegmentAck sequence {} out of range (total {})",
                                        ack_seq, total_segments
                                    )));
                                }

                                let ack_in_current_window = if ack.negative_ack {
                                    let resend_seq = if ack_seq == 0 && window_start == 0 {
                                        0
                                    } else {
                                        ack_seq + 1
                                    };
                                    resend_seq >= window_start && resend_seq < window_end
                                } else {
                                    ack_seq >= window_start && ack_seq < window_end
                                };

                                if !ack_in_current_window {
                                    debug!(
                                        seq = ack.sequence_number,
                                        negative = ack.negative_ack,
                                        window_start,
                                        window_end,
                                        "Ignoring SegmentAck outside current send window"
                                    );
                                    continue;
                                }

                                break ack;
                            }
                            Ok(None) => {
                                return Err(Error::Encoding("SegmentAck channel closed".into()));
                            }
                            Err(_timeout) => {
                                ack_retries += 1;
                                if ack_retries > max_ack_retries {
                                    return Err(Error::Timeout(timeout_duration));
                                }
                                warn!(
                                    attempt = ack_retries,
                                    "Retransmitting segmented request window"
                                );
                                for (seq, segment_data) in segments[window_start..window_end]
                                    .iter()
                                    .enumerate()
                                    .map(|(i, s)| (window_start + i, s))
                                {
                                    let is_last = seq == total_segments - 1;
                                    let pdu = Apdu::ConfirmedRequest(ConfirmedRequestPdu {
                                        segmented: true,
                                        more_follows: !is_last,
                                        segmented_response_accepted: self
                                            .config
                                            .segmented_response_accepted,
                                        max_segments: self.config.max_segments,
                                        max_apdu_length: advertised_max_apdu,
                                        invoke_id,
                                        sequence_number: Some(seq as u8),
                                        proposed_window_size: Some(
                                            self.config.proposed_window_size.max(1),
                                        ),
                                        service_choice,
                                        service_request: segment_data.clone(),
                                    });

                                    let mut buf = BytesMut::with_capacity(remote_max_apdu as usize);
                                    encode_apdu(&mut buf, &pdu)?;

                                    self.send_confirmed_target_apdu(target, &buf).await?;
                                }
                            }
                        }
                    }
                };

                debug!(
                    seq = ack.sequence_number,
                    negative = ack.negative_ack,
                    window = ack.actual_window_size,
                    "Received SegmentAck"
                );

                window_size = ack.actual_window_size.max(1) as usize;

                let ack_seq = ack.sequence_number as usize;
                if ack.negative_ack {
                    neg_ack_retries += 1;
                    if neg_ack_retries > MAX_NEG_ACK_RETRIES {
                        return Err(Error::Segmentation(
                            "too many negative SegmentAck retransmissions".into(),
                        ));
                    }
                    // A first-window negative SegmentACK with sequence 0 is
                    // ambiguous: it can mean segment 0 was the last accepted
                    // segment, or that no segment has been accepted yet. Later
                    // NAK 0 frames are stale for this window and are ignored
                    // before reaching this branch.
                    next_seq = if ack_seq == 0 && window_start == 0 {
                        0
                    } else {
                        ack_seq + 1
                    };
                } else {
                    neg_ack_retries = 0;
                    next_seq = ack_seq + 1;
                }
            }

            timeout(timeout_duration, rx)
                .await
                .map_err(|_| Error::Timeout(timeout_duration))?
                .map_err(|_| Error::Encoding("TSM response channel closed".into()))
        }
        .await;

        {
            let key = (tsm_mac.clone(), invoke_id);
            self.seg_ack_senders.lock().await.remove(&key);
        }

        let response = match result {
            Ok(response) => response,
            Err(e) => {
                let mut tsm = self.tsm.lock().await;
                tsm.cancel_transaction(&tsm_mac, invoke_id);
                return Err(e);
            }
        };

        match response {
            TsmResponse::SimpleAck => Ok(Bytes::new()),
            TsmResponse::ComplexAck { service_data } => Ok(service_data),
            TsmResponse::Error { class, code } => Err(Error::Protocol { class, code }),
            TsmResponse::Reject { reason } => Err(Error::Reject { reason }),
            TsmResponse::Abort { reason } => Err(Error::Abort { reason }),
        }
    }
}
