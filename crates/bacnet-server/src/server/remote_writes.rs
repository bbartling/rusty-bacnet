//! Writes this server makes in other devices on behalf of its own objects: a
//! Command action naming another Device (Clause 12.10.8, #1180), or a Channel
//! member in another device (Clause 12.53.11, #1264).
//!
//! Each write goes out as one unsegmented confirmed WriteProperty. The address
//! comes from the server's device bindings: a configured binding, or an I-Am
//! heard in the last ten minutes. A device with neither is looked for first
//! (#1322): one Who-Is limited to its instance, then a wait of the APDU
//! timeout, from the send, for its I-Am. The Who-Is goes to every network for
//! a device never heard from, or to the network the device's stale
//! observation names, which a Who-Is that draws nothing drops. A write that
//! misses while that Who-Is is out waits on it instead of sending another,
//! and a device gets at most one Who-Is a minute (`binding_probes`), so a
//! write that misses within a minute of a Who-Is that drew nothing fails at
//! once. A write that ends with no binding sends no WriteProperty. A binding
//! routed through the network numbered as this device's own, once that number
//! is known, names a device on this network: the write goes to its MAC with
//! no DNET, not through the router (#1358), since a non-routing device drops
//! an NPDU whose DNET names a network (Clause 6.5.2.1).
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
//! included), Reject or Abort is final, and the caller gets what it said
//! (#1323): the Error's class and code, or the Reject or Abort reason.
//! Nothing is sent while DeviceCommunicationControl restricts initiation, a
//! Who-Is included, since Clause 16.1 lets such a device start no request but
//! I-Am answers and audit notifications: a retry it would block, or one whose
//! observed binding has lapsed, ends the write there and frees its invoke ID.
//! The caller holds no database guard while a write is outstanding or waits
//! for an I-Am, and the binding table's guard is never held across a send or
//! a wait.

use super::binding_probes::{ProbeStep, WhoIsScope};
use super::device_bindings::{DeviceBindingTable, DeviceResolution};
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
    /// No usable binding for the device, and no Who-Is sent for it: the
    /// identifier can't be looked for, a Who-Is for it drew nothing within
    /// the last minute, too many devices are being looked for, or an observed
    /// binding lapsed before a retry.
    Unbound,
    /// No binding for the device, and the Who-Is sent for it drew no I-Am
    /// within the APDU timeout.
    Undiscovered,
    /// The value has no encoding.
    Unencodable,
    /// The request doesn't fit in one APDU this device can send.
    TooLong,
    /// Every invoke ID is leased to another outstanding transaction.
    NoInvokeId,
    /// The server is stopping.
    Stopping,
    /// The device answered with an Error, Reject or Abort, saying this.
    Refused(Refusal),
    /// No answer to the first attempt or any retry.
    Unanswered,
    /// The runner has no network to send on: a run made without a server.
    NoNetwork,
}

impl fmt::Display for RemoteWriteError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let reason = match self {
            Self::Disabled => "initiation is restricted by DeviceCommunicationControl",
            Self::Unbound => "no usable binding for the device",
            Self::Undiscovered => "the device didn't answer a Who-Is",
            Self::Unencodable => "the value has no encoding",
            Self::TooLong => "the request is longer than one APDU",
            Self::NoInvokeId => "no invoke ID is free",
            Self::Stopping => "the server is stopping",
            Self::Refused(refusal) => {
                let answer = Error::from(*refusal);
                return write!(formatter, "the device refused the write: {answer}");
            }
            Self::Unanswered => "the device didn't answer",
            Self::NoNetwork => "no network to send the write on",
        };
        formatter.write_str(reason)
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
    pub(super) comm_state: &'a CommState,
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
        let route = self.route(write.device).await?;
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
            NotificationWorkerResult::Error(refusal) => Err(RemoteWriteError::Refused(refusal)),
            NotificationWorkerResult::Exhausted => Err(RemoteWriteError::Unanswered),
            NotificationWorkerResult::Closed => Err(RemoteWriteError::Stopping),
        }
    }

    /// The route to `device`: its binding, or the one a targeted Who-Is finds
    /// when it has none fresh.
    async fn route(
        &self,
        device: ObjectIdentifier,
    ) -> Result<ConfirmedRecipientRoute, RemoteWriteError> {
        let resolution = self.resolve(&*self.bindings.read().await, device);
        if !can_look_for(device, &resolution) {
            return self.confirmed(resolution, RemoteWriteError::Unbound);
        }
        let (step, scope) = {
            let mut table = self.bindings.write().await;
            // An I-Am may have come in since the read guard went.
            let resolution = self.resolve(&table, device);
            if !can_look_for(device, &resolution) {
                return self.confirmed(resolution, RemoteWriteError::Unbound);
            }
            if self.initiation_restricted() {
                return Err(RemoteWriteError::Disabled);
            }
            let now = tokio::time::Instant::now();
            let step = table.probes.begin(device, now, self.timeout);
            (step, table.who_is_scope(&device))
        };
        let wait = match step {
            ProbeStep::Send(wait) => {
                self.who_is(device, scope, wait.id()).await?;
                wait
            }
            ProbeStep::Join(wait) => wait,
            ProbeStep::HeldOff | ProbeStep::Full => {
                debug!(%device, ?step, "No Who-Is sent for an unbound device");
                return Err(RemoteWriteError::Unbound);
            }
        };
        // Woken by the I-Am or the deadline, the write looks again either way.
        wait.answered().await;
        let resolution = self.resolve(&*self.bindings.read().await, device);
        if let Ok(route) = self.confirmed(resolution, RemoteWriteError::Undiscovered) {
            return Ok(route);
        }
        // A probe withdrawn before its Who-Is went out ends here too.
        if self.initiation_restricted() {
            return Err(RemoteWriteError::Disabled);
        }
        // Nothing answered where the device was last seen, so its next
        // Who-Is asks every network instead.
        self.bindings
            .write()
            .await
            .forget_stale(&device, Instant::now());
        Err(RemoteWriteError::Undiscovered)
    }

    fn resolve(&self, table: &DeviceBindingTable, device: ObjectIdentifier) -> DeviceResolution {
        table.resolve_at(&device, Instant::now(), |mac| {
            self.network.transport().is_broadcast_mac(mac)
        })
    }

    /// The confirmed route `resolution` gives, or `missing` when it gives
    /// none. A binding routed through this network's own number, read now,
    /// is the local device it is (#1358): the write goes straight to its MAC
    /// with no DNET and is answered from there, and one at the link's
    /// broadcast MAC names no device, so it gives no route.
    fn confirmed(
        &self,
        resolution: DeviceResolution,
        missing: RemoteWriteError,
    ) -> Result<ConfirmedRecipientRoute, RemoteWriteError> {
        RecipientRoute::from_device_resolution(resolution)
            .localize(self.network.local_network_number().get(), |mac| {
                self.network.transport().is_broadcast_mac(mac)
            })
            .into_confirmed()
            .ok_or(missing)
    }

    /// Broadcast a Who-Is whose limits are both `device`'s instance across
    /// `scope`, then start probe `probe`'s wait from the send. A failed send
    /// leaves the probe to run out like a silent device's. If
    /// DeviceCommunicationControl has restricted initiation since the probe
    /// started, nothing is sent and the probe is withdrawn.
    async fn who_is(
        &self,
        device: ObjectIdentifier,
        scope: WhoIsScope,
        probe: u64,
    ) -> Result<(), RemoteWriteError> {
        let instance = device.instance_number();
        let mut service = BytesMut::new();
        WhoIsRequest {
            range: Some(DeviceInstanceRange::single(instance)),
        }
        .encode(&mut service);
        let mut apdu = BytesMut::new();
        encode_apdu(
            &mut apdu,
            &Apdu::UnconfirmedRequest(UnconfirmedRequestPdu {
                service_choice: UnconfirmedServiceChoice::WHO_IS,
                service_request: service.freeze(),
            }),
        )
        .expect("valid APDU encoding");
        let scope = scope.localize(self.network.local_network_number().get());
        let priority = NetworkPriority::NORMAL;
        if self.initiation_restricted() {
            self.bindings.write().await.probes.withdraw(&device, probe);
            return Err(RemoteWriteError::Disabled);
        }
        let sent = match scope {
            WhoIsScope::Local => self.network.broadcast_apdu(&apdu, false, priority).await,
            WhoIsScope::Remote(network) => {
                self.network
                    .broadcast_to_network(&apdu, network, false, priority)
                    .await
            }
            WhoIsScope::Global => {
                self.network
                    .broadcast_global_apdu(&apdu, false, priority)
                    .await
            }
        };
        match sent {
            Ok(()) => debug!(%device, ?scope, "Who-Is for an unbound device sent"),
            Err(error) => warn!(
                %error,
                %device,
                ?scope,
                "Who-Is for an unbound device not sent"
            ),
        }
        let now = tokio::time::Instant::now();
        let mut table = self.bindings.write().await;
        table.probes.sent(&device, probe, now, self.timeout);
        Ok(())
    }

    fn initiation_restricted(&self) -> bool {
        self.comm_state.initiation_restricted()
    }
}

/// Whether a write may look for `device` with a Who-Is: it has no binding,
/// or only a stale one, and its instance isn't the wildcard, which in a
/// Who-Is calls on unconfigured devices instead (Clause 16.11).
fn can_look_for(device: ObjectIdentifier, resolution: &DeviceResolution) -> bool {
    matches!(
        resolution,
        DeviceResolution::Unknown | DeviceResolution::Stale
    ) && device.instance_number() != ObjectIdentifier::WILDCARD_INSTANCE
}

/// One attempt: the request to the bound peer, a device on this network
/// included, or through the binding's router to a device on another network.
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
