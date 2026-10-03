//! Writes this server makes in other devices on behalf of its own objects: a
//! Command action naming another Device (Clause 12.10.8, #1180).
//!
//! Each write goes out as one unsegmented confirmed WriteProperty. The address
//! comes from the server's device bindings only, a configured binding or an
//! I-Am heard in the last ten minutes; nothing sends a Who-Is, so an unknown
//! or stale device fails at once with nothing sent.
//!
//! The invoke ID is leased from the same device-wide pool as confirmed
//! notifications (and, in an endpoint, client requests), so no two
//! outstanding transactions share one, and the answer comes back through the
//! notifications' dispatch fast path. The lease carries the peer and the
//! WriteProperty service: only that peer's answer ends it, and a SimpleACK or
//! Error only when it names WriteProperty, so a late answer to a notification
//! that once held the same invoke ID can't complete the write.
//!
//! Each attempt waits `cov_retry_timeout_ms` for an answer, and only silence
//! earns another attempt, up to the server's three retries; an Error (BUSY
//! included), Reject or Abort is final. Nothing is sent while
//! DeviceCommunicationControl restricts initiation: a retry it would block,
//! or one whose observed binding has lapsed, ends the write there and frees
//! its invoke ID. The caller holds no database guard while a write is
//! outstanding.

use super::device_bindings::DeviceBindingTable;
use super::event_recipient_route::{ConfirmedRecipientRoute, RecipientRoute};
use super::notification_transactions::{run_attempts, Attempt, NotificationReserveError};
use super::*;
use bacnet_services::write_property::WritePropertyRequest;
use bacnet_types::constructed::BACnetActionCommand;
use std::fmt;

/// Octets of an unsegmented Confirmed-Request header: type, segmentation
/// limits, invoke ID and service choice.
const CONFIRMED_HEADER_LEN: usize = 4;

const WRITE_PROPERTY: ConfirmedServiceChoice = ConfirmedServiceChoice::WRITE_PROPERTY;

/// Why a write in another device was not made.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum RemoteWriteError {
    /// DeviceCommunicationControl restricts initiation: nothing was sent, or
    /// the write ended at the first retry after it took effect.
    Disabled,
    /// No usable binding for the device: none configured, no I-Am heard in
    /// the last ten minutes, or an observed one that lapsed before a retry.
    Unbound,
    /// The value has no encoding.
    Unencodable,
    /// The request doesn't fit in one APDU this device can send.
    TooLong,
    /// Every invoke ID is leased to another outstanding transaction.
    NoInvokeId,
    /// The server is stopping.
    Stopping,
    /// The device answered with an Error, Reject or Abort.
    Refused,
    /// No answer to the first attempt or any retry.
    Unanswered,
    /// The runner has no network to send on: a run made without a server.
    NoNetwork,
}

impl fmt::Display for RemoteWriteError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Disabled => "initiation is restricted by DeviceCommunicationControl",
            Self::Unbound => "no usable binding for the device",
            Self::Unencodable => "the value has no encoding",
            Self::TooLong => "the request is longer than one APDU",
            Self::NoInvokeId => "no invoke ID is free",
            Self::Stopping => "the server is stopping",
            Self::Refused => "the device refused the write",
            Self::Unanswered => "the device didn't answer",
            Self::NoNetwork => "no network to send the write on",
        })
    }
}

/// One WriteProperty to send to another device.
#[derive(Debug, Clone, PartialEq)]
pub(crate) struct RemoteWrite {
    /// The Device that holds the target object.
    pub(crate) device: ObjectIdentifier,
    /// The request, its value already encoded.
    pub(crate) request: WritePropertyRequest,
}

impl RemoteWrite {
    /// The write `command` makes in `device`.
    pub(crate) fn for_command(
        device: ObjectIdentifier,
        command: &BACnetActionCommand,
    ) -> Result<Self, RemoteWriteError> {
        let mut value = BytesMut::new();
        encode_property_value(&mut value, &command.property_value)
            .map_err(|_| RemoteWriteError::Unencodable)?;
        Ok(Self {
            device,
            request: WritePropertyRequest {
                object_identifier: command.object_identifier,
                property_identifier: command.property_identifier,
                property_array_index: command.property_array_index,
                property_value: value.to_vec(),
                priority: command.priority,
            },
        })
    }
}

/// The server handles a write in another device needs.
pub(super) struct RemoteWriter<'a, T: TransportPort + 'static> {
    pub(super) network: &'a Arc<NetworkLayer<T>>,
    pub(super) transactions: &'a Arc<NotificationTransactions>,
    pub(super) bindings: &'a RwLock<DeviceBindingTable>,
    pub(super) comm_state: &'a AtomicU8,
    /// How long each attempt waits for the answer.
    pub(super) timeout: Duration,
    /// Attempts after the first, each earned by silence.
    pub(super) retries: u8,
    /// The longest APDU this device sends or takes.
    pub(super) max_apdu: u32,
}

impl<T: TransportPort + 'static> RemoteWriter<'_, T> {
    /// Send `write` and wait for the device's answer.
    pub(super) async fn write(&self, write: &RemoteWrite) -> Result<(), RemoteWriteError> {
        if self.initiation_restricted() {
            return Err(RemoteWriteError::Disabled);
        }
        let resolution = {
            let table = self.bindings.read().await;
            table.resolve_at(&write.device, Instant::now(), |mac| {
                self.network.transport().is_broadcast_mac(mac)
            })
        };
        let route = RecipientRoute::from_device_resolution(resolution)
            .into_confirmed()
            .ok_or(RemoteWriteError::Unbound)?;
        let mut service = BytesMut::new();
        write
            .request
            .encode(&mut service)
            .map_err(|_| RemoteWriteError::Unencodable)?;
        // Checked before an invoke ID is leased.
        let capacity = usize::try_from(self.max_apdu).unwrap_or(usize::MAX);
        if CONFIRMED_HEADER_LEN + service.len() > capacity {
            return Err(RemoteWriteError::TooLong);
        }
        let (operation, answer) = match self
            .transactions
            .reserve(route.canonical_peer.clone(), WRITE_PROPERTY)
        {
            Ok(reservation) => reservation,
            Err(NotificationReserveError::Closed) => return Err(RemoteWriteError::Stopping),
            Err(_) => return Err(RemoteWriteError::NoInvokeId),
        };
        let invoke_id = operation.invoke_id();
        let mut apdu = BytesMut::new();
        encode_apdu(
            &mut apdu,
            &Apdu::ConfirmedRequest(ConfirmedRequestPdu {
                segmented: false,
                more_follows: false,
                segmented_response_accepted: false,
                max_segments: None,
                max_apdu_length: apdu::max_apdu_header_at_or_below(self.max_apdu)
                    .expect("validated local APDU capacity"),
                invoke_id,
                sequence_number: None,
                proposed_window_size: None,
                service_choice: WRITE_PROPERTY,
                service_request: service.freeze(),
            }),
        )
        .expect("valid APDU encoding");
        let (apdu, route, network) = (&apdu, &route, self.network);
        let outcome = run_attempts(operation, answer, self.timeout, self.retries, |attempt| {
            // A retry is a send too: DCC and the binding's lifetime are
            // checked again before each one, and either ends the write.
            let withdrawn = if self.initiation_restricted() {
                Some(RemoteWriteError::Disabled)
            } else if route
                .freshness
                .is_some_and(|freshness| !freshness.permits_attempt_at(tokio::time::Instant::now()))
            {
                Some(RemoteWriteError::Unbound)
            } else {
                None
            };
            async move {
                if let Some(reason) = withdrawn {
                    return Attempt::Withdrawn(reason);
                }
                match send(network, apdu, route, invoke_id, attempt).await {
                    Ok(()) => Attempt::Sent,
                    Err(()) => Attempt::NotSent,
                }
            }
        })
        .await?;
        match outcome {
            NotificationWorkerResult::Ack => Ok(()),
            NotificationWorkerResult::Error => Err(RemoteWriteError::Refused),
            NotificationWorkerResult::Exhausted => Err(RemoteWriteError::Unanswered),
            NotificationWorkerResult::Closed => Err(RemoteWriteError::Stopping),
        }
    }

    fn initiation_restricted(&self) -> bool {
        self.comm_state.load(Ordering::Acquire) >= 1
    }
}

/// One attempt: the request to the bound peer, or through the binding's
/// router to a device on another network.
async fn send<T: TransportPort + 'static>(
    network: &NetworkLayer<T>,
    apdu: &[u8],
    route: &ConfirmedRecipientRoute,
    invoke_id: u8,
    attempt: u8,
) -> Result<(), ()> {
    let priority = NetworkPriority::NORMAL;
    let sent = match (&route.local_target, &route.remote) {
        (Some(mac), None) => network.send_apdu(apdu, mac, true, priority).await,
        (None, Some((dnet, dadr, Some(router)))) => {
            network
                .send_apdu_routed(apdu, *dnet, dadr, router, true, priority)
                .await
        }
        // A Device binding always names its next hop.
        _ => return Err(()),
    };
    match &sent {
        Ok(()) => debug!(invoke_id, attempt, "WriteProperty to another device sent"),
        Err(error) => warn!(
            %error,
            invoke_id, attempt, "WriteProperty to another device not sent"
        ),
    }
    sent.map_err(|_| ())
}
