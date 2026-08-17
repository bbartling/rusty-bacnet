use super::*;
use bacnet_encoding::apdu::MINIMUM_MESSAGE_SIZE;

/// Which term of Clause 5.2.1.2's minimum bound the transmittable length down.
///
/// Named separately so the error blames the right one. The checked value is a
/// minimum over several terms, and the peer is only sometimes the binding one:
/// BACnet/SC recomputes its own limit from the hub's Connect-Accept, so a
/// transport can fall below the floor while the peer is perfectly conformant.
enum LengthBoundedBy {
    /// A length advertised by a discovered peer, from I-Am.
    DiscoveredPeer(u16),
    /// This client's own configured maximum.
    LocalConfig(u16),
    /// The data link, after any routed NPDU header.
    Transport(u16),
}

impl core::fmt::Display for LengthBoundedBy {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::DiscoveredPeer(v) => {
                write!(f, "the peer's advertised Max APDU Length Accepted of {v}")
            }
            Self::LocalConfig(v) => write!(f, "this client's configured maximum of {v}"),
            Self::Transport(v) => write!(f, "the transport's limit of {v}"),
        }
    }
}

/// Reject a maximum transmittable length no conformant device could accept.
///
/// Clause 5.2.1.2 derives this length as the smallest of the local capability,
/// the internetwork limit, and "(c) the maximum APDU size accepted by the
/// remote peer device, which must be at least 50 octets". Below that floor no
/// conformant APDU can be formed at all. Clause 20.1.2.5 gives the same number
/// a name, spelling the lowest max-APDU-length-accepted code `B'0000'` as "Up
/// to MinimumMessageSize (50 octets)".
///
/// The check is a floor, not membership of the six values Clause 20.1.2.5
/// encodes. A discovered peer's length comes from I-Am's `Max APDU Length
/// Accepted`, an Unsigned octet count rather than the four-bit code, and
/// Clause 20.1.2.5 notes the true value "may be larger than indicated in this
/// parameter" — so 600 and 1500 are legitimate and must not be rejected.
///
/// Failing rather than clamping up to 50 keeps the client from inventing a
/// capability the peer never claimed: a device advertising less than 50 is
/// already non-conformant, and a typed error names that where a silent clamp
/// would send it frames it said it cannot hold.
fn check_transmittable_length(peer_or_local: LengthBoundedBy, transport: u16) -> Result<(), Error> {
    let advertised = match peer_or_local {
        LengthBoundedBy::DiscoveredPeer(v) | LengthBoundedBy::LocalConfig(v) => v,
        LengthBoundedBy::Transport(v) => v,
    };
    let combined = advertised.min(transport);
    if combined >= MINIMUM_MESSAGE_SIZE {
        return Ok(());
    }
    let binding = if transport < advertised {
        LengthBoundedBy::Transport(transport)
    } else {
        peer_or_local
    };
    Err(Error::Encoding(format!(
        "maximum transmittable length {combined} is below the {MINIMUM_MESSAGE_SIZE}-octet \
         MinimumMessageSize every BACnet device accepts (Clause 5.2.1.2); the binding limit is \
         {binding}"
    )))
}

#[cfg(test)]
mod transmittable_length_tests {
    use super::{check_transmittable_length, LengthBoundedBy};

    #[test]
    fn conformant_lengths_pass() {
        for advertised in [50u16, 128, 206, 480, 1024, 1476] {
            assert!(
                check_transmittable_length(LengthBoundedBy::DiscoveredPeer(advertised), 1476)
                    .is_ok(),
                "{advertised} is at or above MinimumMessageSize"
            );
        }
    }

    /// I-Am carries an Unsigned octet count, not the four-bit code, and Clause
    /// 20.1.2.5 says the true value "may be larger than indicated in this
    /// parameter" — so values outside the six encodings are legitimate.
    #[test]
    fn lengths_outside_the_encoded_set_are_not_rejected() {
        for advertised in [51u16, 600, 1500, u16::MAX] {
            assert!(
                check_transmittable_length(LengthBoundedBy::DiscoveredPeer(advertised), u16::MAX)
                    .is_ok(),
                "{advertised} is conformant even though it is not one of the six encodings"
            );
        }
    }

    /// The error must blame whichever term actually bound the minimum. The peer
    /// is only sometimes that term: BACnet/SC recomputes its own limit from the
    /// hub's Connect-Accept, so a transport can fall below the floor while the
    /// peer is entirely conformant.
    #[test]
    fn the_error_names_the_binding_term() {
        let peer_bound =
            check_transmittable_length(LengthBoundedBy::DiscoveredPeer(3), 1476).unwrap_err();
        assert!(
            peer_bound.to_string().contains("peer's advertised"),
            "peer is the binding term here, got: {peer_bound}"
        );

        let transport_bound =
            check_transmittable_length(LengthBoundedBy::DiscoveredPeer(1476), 48).unwrap_err();
        assert!(
            transport_bound.to_string().contains("transport's limit"),
            "transport is the binding term here and the peer is conformant, got: {transport_bound}"
        );
        assert!(
            !transport_bound.to_string().contains("peer's advertised"),
            "must not blame a conformant peer for the transport's limit"
        );
    }
}

impl<T: TransportPort + 'static> BACnetClient<T> {
    /// Send a confirmed request and wait for the response.
    ///
    /// Returns the service response data (empty for SimpleAck). Automatically
    /// uses segmented transfer when the payload exceeds the remote device's
    /// max APDU length.
    pub async fn confirmed_request(
        &self,
        destination_mac: &[u8],
        service_choice: ConfirmedServiceChoice,
        service_data: &[u8],
    ) -> Result<Bytes, Error> {
        self.confirmed_request_inner(
            ConfirmedTarget::Local {
                mac: destination_mac,
            },
            service_choice,
            service_data,
        )
        .await
    }

    /// Send a confirmed request routed through a BACnet router.
    ///
    /// The NPDU is sent as a unicast to `router_mac` with DNET/DADR set so
    /// the router forwards it to `dest_network`/`dest_mac`.
    pub async fn confirmed_request_routed(
        &self,
        router_mac: &[u8],
        dest_network: u16,
        dest_mac: &[u8],
        service_choice: ConfirmedServiceChoice,
        service_data: &[u8],
    ) -> Result<Bytes, Error> {
        self.confirmed_request_inner(
            ConfirmedTarget::Routed {
                router_mac,
                dest_network,
                dest_mac,
            },
            service_choice,
            service_data,
        )
        .await
    }

    pub(super) async fn confirmed_request_inner(
        &self,
        target: ConfirmedTarget<'_>,
        service_choice: ConfirmedServiceChoice,
        service_data: &[u8],
    ) -> Result<Bytes, Error> {
        let tsm_mac = target.tsm_mac();
        let unsegmented_apdu_size = 4 + service_data.len();
        let target_transport_max_apdu = self.target_transport_max_apdu_length(target);

        match target {
            ConfirmedTarget::Local { mac } => {
                let (remote_max_apdu, remote_max_segments, advertised) = {
                    let dt = self.device_table.lock().await;
                    let device = dt.get_by_mac(mac);
                    let max_apdu = device
                        .map(|d| u16::try_from(d.max_apdu_length).unwrap_or(u16::MAX))
                        .unwrap_or(self.config.max_apdu_length);
                    let max_seg = device.and_then(|d| d.max_segments_accepted);
                    let advertised = if device.is_some() {
                        LengthBoundedBy::DiscoveredPeer(max_apdu)
                    } else {
                        LengthBoundedBy::LocalConfig(max_apdu)
                    };
                    (max_apdu.min(target_transport_max_apdu), max_seg, advertised)
                };
                check_transmittable_length(advertised, target_transport_max_apdu)?;
                if unsegmented_apdu_size > remote_max_apdu as usize {
                    return self
                        .segmented_confirmed_request(
                            target,
                            service_choice,
                            service_data,
                            remote_max_apdu,
                            remote_max_segments,
                        )
                        .await;
                }
            }
            ConfirmedTarget::Routed { .. } => {
                let remote_max_apdu = self.config.max_apdu_length.min(target_transport_max_apdu);
                // Deliberately the local configuration, not a peer value: this
                // branch never consults the device table, so a routed peer's
                // own advertised limit is still unenforced. Tracked separately.
                check_transmittable_length(
                    LengthBoundedBy::LocalConfig(self.config.max_apdu_length),
                    target_transport_max_apdu,
                )?;
                if unsegmented_apdu_size > remote_max_apdu as usize {
                    return self
                        .segmented_confirmed_request(
                            target,
                            service_choice,
                            service_data,
                            remote_max_apdu,
                            None,
                        )
                        .await;
                }
            }
        }

        let advertised_max_apdu = self.advertised_max_apdu_length_for_target(target)?;
        let (invoke_id, rx) = {
            let mut tsm = self.tsm.lock().await;
            let invoke_id = tsm.allocate_invoke_id(&tsm_mac).ok_or_else(|| {
                Error::Encoding("all invoke IDs exhausted for destination".into())
            })?;
            let rx = tsm.register_transaction(tsm_mac.clone(), invoke_id, service_choice);
            (invoke_id, rx)
        };

        // Guard cleans up invoke ID if this task is cancelled/aborted
        let mut guard =
            crate::tsm::TsmGuard::new(std::sync::Arc::clone(&self.tsm), tsm_mac.clone(), invoke_id);

        let pdu = Apdu::ConfirmedRequest(ConfirmedRequestPdu {
            segmented: false,
            more_follows: false,
            segmented_response_accepted: self.config.segmented_response_accepted,
            max_segments: self.config.max_segments,
            max_apdu_length: advertised_max_apdu,
            invoke_id,
            sequence_number: None,
            proposed_window_size: None,
            service_choice,
            service_request: Bytes::copy_from_slice(service_data),
        });

        let mut buf = BytesMut::with_capacity(6 + service_data.len());
        encode_apdu(&mut buf, &pdu)?;

        let timeout_duration = Duration::from_millis(self.config.apdu_timeout_ms);
        let max_retries = self.config.apdu_retries;
        let mut attempts: u8 = 0;
        let mut rx = rx;

        loop {
            let send_result = match &target {
                ConfirmedTarget::Local { mac } => {
                    self.network
                        .send_apdu(&buf, mac, true, NetworkPriority::NORMAL)
                        .await
                }
                ConfirmedTarget::Routed {
                    router_mac,
                    dest_network,
                    dest_mac,
                } => {
                    self.network
                        .send_apdu_routed(
                            &buf,
                            *dest_network,
                            dest_mac,
                            router_mac,
                            true,
                            NetworkPriority::NORMAL,
                        )
                        .await
                }
            };
            if let Err(e) = send_result {
                guard.mark_completed();
                let mut tsm = self.tsm.lock().await;
                tsm.cancel_transaction(&tsm_mac, invoke_id);
                return Err(e);
            }

            match timeout(timeout_duration, &mut rx).await {
                Ok(Ok(response)) => {
                    guard.mark_completed();
                    return match response {
                        TsmResponse::SimpleAck => Ok(Bytes::new()),
                        TsmResponse::ComplexAck { service_data } => Ok(service_data),
                        TsmResponse::Error { class, code } => Err(Error::Protocol { class, code }),
                        TsmResponse::Reject { reason } => Err(Error::Reject { reason }),
                        TsmResponse::Abort { reason } => Err(Error::Abort { reason }),
                    };
                }
                Ok(Err(_)) => {
                    guard.mark_completed();
                    return Err(Error::Encoding("TSM response channel closed".into()));
                }
                Err(_timeout) => {
                    attempts += 1;
                    if attempts > max_retries {
                        guard.mark_completed();
                        let mut tsm = self.tsm.lock().await;
                        tsm.cancel_transaction(&tsm_mac, invoke_id);
                        return Err(Error::Timeout(timeout_duration));
                    }
                    debug!(
                        invoke_id,
                        attempt = attempts,
                        max_retries,
                        "APDU timeout, retrying confirmed request"
                    );
                }
            }
        }
    }

    pub(super) async fn send_confirmed_target_apdu(
        &self,
        target: ConfirmedTarget<'_>,
        apdu: &[u8],
    ) -> Result<(), Error> {
        match target {
            ConfirmedTarget::Local { mac } => {
                self.network
                    .send_apdu(apdu, mac, true, NetworkPriority::NORMAL)
                    .await
            }
            ConfirmedTarget::Routed {
                router_mac,
                dest_network,
                dest_mac,
            } => {
                self.network
                    .send_apdu_routed(
                        apdu,
                        dest_network,
                        dest_mac,
                        router_mac,
                        true,
                        NetworkPriority::NORMAL,
                    )
                    .await
            }
        }
    }

    pub(super) fn target_transport_max_apdu_length(&self, target: ConfirmedTarget<'_>) -> u16 {
        self.network
            .transport()
            .max_apdu_length()
            .saturating_sub(target.additional_npdu_header_len())
    }

    pub(super) fn advertised_max_apdu_length_for_target(
        &self,
        target: ConfirmedTarget<'_>,
    ) -> Result<u16, Error> {
        cap_max_apdu_to_transport(
            self.config.max_apdu_length,
            self.target_transport_max_apdu_length(target),
        )
    }

    /// Send an unconfirmed request (fire-and-forget) to a specific destination.
    pub async fn unconfirmed_request(
        &self,
        destination_mac: &[u8],
        service_choice: UnconfirmedServiceChoice,
        service_data: &[u8],
    ) -> Result<(), Error> {
        let pdu = Apdu::UnconfirmedRequest(bacnet_encoding::apdu::UnconfirmedRequest {
            service_choice,
            service_request: Bytes::copy_from_slice(service_data),
        });

        let mut buf = BytesMut::with_capacity(2 + service_data.len());
        encode_apdu(&mut buf, &pdu)?;

        self.network
            .send_apdu(&buf, destination_mac, false, NetworkPriority::NORMAL)
            .await
    }

    /// Broadcast an unconfirmed request on the local network.
    pub async fn broadcast_unconfirmed(
        &self,
        service_choice: UnconfirmedServiceChoice,
        service_data: &[u8],
    ) -> Result<(), Error> {
        let pdu = Apdu::UnconfirmedRequest(bacnet_encoding::apdu::UnconfirmedRequest {
            service_choice,
            service_request: Bytes::copy_from_slice(service_data),
        });

        let mut buf = BytesMut::with_capacity(2 + service_data.len());
        encode_apdu(&mut buf, &pdu)?;

        self.network
            .broadcast_apdu(&buf, false, NetworkPriority::NORMAL)
            .await
    }

    /// Broadcast an unconfirmed request globally (DNET=0xFFFF).
    pub async fn broadcast_global_unconfirmed(
        &self,
        service_choice: UnconfirmedServiceChoice,
        service_data: &[u8],
    ) -> Result<(), Error> {
        let pdu = Apdu::UnconfirmedRequest(bacnet_encoding::apdu::UnconfirmedRequest {
            service_choice,
            service_request: Bytes::copy_from_slice(service_data),
        });

        let mut buf = BytesMut::with_capacity(2 + service_data.len());
        encode_apdu(&mut buf, &pdu)?;

        self.network
            .broadcast_global_apdu(&buf, false, NetworkPriority::NORMAL)
            .await
    }

    /// Broadcast an unconfirmed request to a specific remote network.
    pub async fn broadcast_network_unconfirmed(
        &self,
        service_choice: UnconfirmedServiceChoice,
        service_data: &[u8],
        dest_network: u16,
    ) -> Result<(), Error> {
        let pdu = Apdu::UnconfirmedRequest(bacnet_encoding::apdu::UnconfirmedRequest {
            service_choice,
            service_request: Bytes::copy_from_slice(service_data),
        });

        let mut buf = BytesMut::with_capacity(2 + service_data.len());
        encode_apdu(&mut buf, &pdu)?;

        self.network
            .broadcast_to_network(&buf, dest_network, false, NetworkPriority::NORMAL)
            .await
    }
}
