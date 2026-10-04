use super::binding_probes::{BindingProbes, WhoIsScope};
use super::event_recipient_route::RecipientRoute;
use super::*;

/// Maximum number of configured and observed device bindings held by a server.
pub(super) const MAX_DEVICE_BINDINGS: usize = 4096;

/// Freshness window for passively observed I-Am bindings.
pub(super) const OBSERVED_BINDING_TTL: Duration = Duration::from_secs(10 * 60);

#[derive(Debug, Clone, PartialEq, Eq)]
enum DeviceBindingTarget {
    Local {
        peer_mac: MacAddr,
    },
    Routed {
        network: u16,
        final_mac: MacAddr,
        router_mac: MacAddr,
    },
}

/// One explicitly configured unicast route to a Device object.
///
/// Constructed values are transport-neutral. A builder performs the remaining
/// concrete data-link broadcast check before the transport is started.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeviceBinding {
    device: ObjectIdentifier,
    target: DeviceBindingTarget,
}

impl DeviceBinding {
    /// Create a binding to a peer on the server's local network.
    pub fn local(device: ObjectIdentifier, peer_mac: impl AsRef<[u8]>) -> Result<Self, Error> {
        validate_device_identifier(device)?;
        let peer_mac = MacAddr::from_slice(peer_mac.as_ref());
        if peer_mac.is_empty() {
            return Err(binding_error("local peer MAC must be non-empty"));
        }
        Ok(Self {
            device,
            target: DeviceBindingTarget::Local { peer_mac },
        })
    }

    /// Create a routed binding with a final network/address and local router.
    pub fn routed(
        device: ObjectIdentifier,
        network: u16,
        final_mac: impl AsRef<[u8]>,
        router_mac: impl AsRef<[u8]>,
    ) -> Result<Self, Error> {
        validate_device_identifier(device)?;
        if !(1..=0xFFFE).contains(&network) {
            return Err(binding_error("routed network must be in 1..=65534"));
        }
        let final_mac = MacAddr::from_slice(final_mac.as_ref());
        if final_mac.is_empty() {
            return Err(binding_error("routed final MAC must be non-empty"));
        }
        let router_mac = MacAddr::from_slice(router_mac.as_ref());
        if router_mac.is_empty() {
            return Err(binding_error("routed router MAC must be non-empty"));
        }
        Ok(Self {
            device,
            target: DeviceBindingTarget::Routed {
                network,
                final_mac,
                router_mac,
            },
        })
    }
}

fn binding_error(message: &str) -> Error {
    Error::Encoding(format!("invalid device binding: {message}"))
}

fn validate_device_identifier(device: ObjectIdentifier) -> Result<(), Error> {
    if device.object_type() != ObjectType::DEVICE {
        return Err(binding_error("identifier must name a Device object"));
    }
    Ok(())
}

pub(super) fn register_configured_binding(
    bindings: &mut Vec<DeviceBinding>,
    binding: DeviceBinding,
) -> Result<(), Error> {
    if bindings.len() >= MAX_DEVICE_BINDINGS {
        return Err(binding_error("configured binding capacity exceeded"));
    }
    if bindings
        .iter()
        .any(|configured| configured.device == binding.device)
    {
        return Err(binding_error("duplicate configured Device identifier"));
    }
    bindings.push(binding);
    Ok(())
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) enum DeviceResolution {
    ResolvedLocal {
        peer_mac: MacAddr,
        freshness: BindingFreshness,
    },
    ResolvedRouted {
        network: u16,
        final_mac: MacAddr,
        router_mac: MacAddr,
        freshness: BindingFreshness,
    },
    Unknown,
    Stale,
    Invalid,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum BindingFreshness {
    Configured,
    ObservedUntil(tokio::time::Instant),
}

impl BindingFreshness {
    pub(super) fn permits_attempt_at(self, now: tokio::time::Instant) -> bool {
        match self {
            Self::Configured => true,
            Self::ObservedUntil(deadline) => now < deadline,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum ObservationOutcome {
    Inserted,
    Refreshed,
    ConfiguredPreserved,
    RejectedInvalid,
    RejectedCapacity,
}

#[derive(Debug, Clone)]
enum BindingEntry {
    Configured(DeviceBindingTarget),
    Observed {
        target: DeviceBindingTarget,
        observed_at: Instant,
    },
}

#[derive(Debug, Default)]
pub(super) struct DeviceBindingTable {
    entries: HashMap<ObjectIdentifier, BindingEntry>,
    /// Targeted Who-Is requests out or held off, kept under the same guard
    /// so an I-Am can wake the writes waiting on them (#1322).
    pub(super) probes: BindingProbes,
}

impl DeviceBindingTable {
    /// Snapshot original sender and correlation while holding only the binding
    /// guard. `local_network` is this network's own number, which
    /// [`Self::source_binding`] matches against.
    pub(super) fn command_origin(
        &self,
        immediate: &[u8],
        routed: Option<&NpduAddress>,
        local_network: Option<u16>,
        is_broadcast: impl Fn(&[u8]) -> bool,
    ) -> bacnet_objects::command_source::CommandOrigin {
        bacnet_objects::command_source::CommandOrigin::Remote {
            actual_address: bacnet_types::constructed::BACnetAddress {
                network_number: routed.map_or(0, |source| source.network),
                mac_address: routed.map_or_else(
                    || MacAddr::from_slice(immediate),
                    |source| source.mac_address.clone(),
                ),
            },
            binding: self.source_binding(immediate, routed, local_network, is_broadcast),
        }
    }

    /// Prefer a known, unambiguous Device identity in target Audit records.
    /// This is address correlation, never authentication of a principal.
    pub(super) fn source_device(
        &self,
        immediate: &[u8],
        routed: Option<&NpduAddress>,
        local_network: Option<u16>,
        is_broadcast: impl Fn(&[u8]) -> bool,
    ) -> Option<ObjectIdentifier> {
        match self.source_binding(immediate, routed, local_network, is_broadcast) {
            bacnet_objects::command_source::CommandDeviceBinding::Unique(device) => Some(device),
            _ => None,
        }
    }

    /// The Device whose binding names a request's source, when exactly one
    /// does. A routed binding names a request relayed with its network and
    /// final MAC as SNET and SADR. A local binding names a request from its
    /// MAC with no SNET (Clause 6.2.2), and, once `local_network`, this
    /// network's own number, is known, one relayed with that number and its
    /// MAC as SNET and SADR: a router here passing a peer's request back onto
    /// this network adds that pair (Clause 6.5.4), and network numbers are
    /// unique, so both forms name the same node. A binding routed through
    /// `local_network` is the local binding it is (#1404), as sends to it
    /// take it ([`RecipientRoute::localize`], #1358).
    pub(super) fn source_binding(
        &self,
        immediate: &[u8],
        routed: Option<&NpduAddress>,
        local_network: Option<u16>,
        is_broadcast: impl Fn(&[u8]) -> bool,
    ) -> bacnet_objects::command_source::CommandDeviceBinding {
        use bacnet_objects::command_source::CommandDeviceBinding;
        let now = Instant::now();
        let mut matched = None;
        for device in self.entries.keys() {
            let resolution = self.resolve_at(device, now, &is_broadcast);
            let route = RecipientRoute::from_device_resolution(resolution)
                .localize(local_network, &is_broadcast);
            let matches = match (route, routed) {
                (RecipientRoute::BoundLocalUnicast { mac, .. }, None) => {
                    mac.as_slice() == immediate
                }
                (RecipientRoute::BoundLocalUnicast { mac, .. }, Some(source)) => {
                    Some(source.network) == local_network && mac == source.mac_address
                }
                (RecipientRoute::BoundRoutedUnicast { network, mac, .. }, Some(source)) => {
                    network == source.network && mac == source.mac_address
                }
                _ => false,
            };
            if matches {
                if matched.is_some() {
                    return CommandDeviceBinding::Ambiguous;
                }
                matched = Some(*device);
            }
        }
        matched.map_or(CommandDeviceBinding::Unknown, CommandDeviceBinding::Unique)
    }

    pub(super) fn new() -> Self {
        Self::default()
    }

    pub(super) fn from_configured(
        bindings: Vec<DeviceBinding>,
        is_broadcast: impl Fn(&[u8]) -> bool,
    ) -> Result<Self, Error> {
        let mut table = Self::new();
        for binding in bindings {
            table.insert_configured(binding, &is_broadcast)?;
        }
        Ok(table)
    }

    /// Immutable configured routes, already validated against the concrete link.
    pub(super) fn configured_resolutions(
        &self,
    ) -> impl Iterator<Item = (ObjectIdentifier, DeviceResolution)> + '_ {
        self.entries
            .iter()
            .filter(|(_, entry)| matches!(entry, BindingEntry::Configured(_)))
            .map(|(device, _)| (*device, self.resolve_at(device, Instant::now(), |_| false)))
    }

    #[cfg(test)]
    pub(super) fn len(&self) -> usize {
        self.entries.len()
    }

    pub(super) fn insert_configured(
        &mut self,
        binding: DeviceBinding,
        is_broadcast: impl Fn(&[u8]) -> bool,
    ) -> Result<(), Error> {
        validate_device_identifier(binding.device)?;
        if !target_is_usable(&binding.target, &is_broadcast) {
            return Err(binding_error(
                "local peer or next-hop router is a broadcast address",
            ));
        }
        if self.entries.contains_key(&binding.device) {
            return Err(binding_error("duplicate configured Device identifier"));
        }
        if self.entries.len() >= MAX_DEVICE_BINDINGS {
            return Err(binding_error("configured binding capacity exceeded"));
        }
        self.entries
            .insert(binding.device, BindingEntry::Configured(binding.target));
        Ok(())
    }

    pub(super) fn observe_i_am_at(
        &mut self,
        device: ObjectIdentifier,
        source_mac: &[u8],
        source_network: Option<&NpduAddress>,
        now: Instant,
        is_broadcast: impl Fn(&[u8]) -> bool,
    ) -> ObservationOutcome {
        if validate_device_identifier(device).is_err() {
            return ObservationOutcome::RejectedInvalid;
        }
        let target = match source_network {
            None => DeviceBindingTarget::Local {
                peer_mac: MacAddr::from_slice(source_mac),
            },
            Some(source)
                if (1..=0xFFFE).contains(&source.network) && !source.mac_address.is_empty() =>
            {
                DeviceBindingTarget::Routed {
                    network: source.network,
                    final_mac: source.mac_address.clone(),
                    router_mac: MacAddr::from_slice(source_mac),
                }
            }
            Some(_) => return ObservationOutcome::RejectedInvalid,
        };
        if !target_is_usable(&target, &is_broadcast) {
            return ObservationOutcome::RejectedInvalid;
        }

        let outcome = self.record_observation(device, target, now);
        if matches!(
            outcome,
            ObservationOutcome::Inserted | ObservationOutcome::Refreshed
        ) {
            self.probes.answer(&device);
        }
        outcome
    }

    fn record_observation(
        &mut self,
        device: ObjectIdentifier,
        target: DeviceBindingTarget,
        now: Instant,
    ) -> ObservationOutcome {
        match self.entries.get_mut(&device) {
            Some(BindingEntry::Configured(_)) => ObservationOutcome::ConfiguredPreserved,
            Some(BindingEntry::Observed {
                target: observed,
                observed_at,
            }) => {
                *observed = target;
                *observed_at = now;
                ObservationOutcome::Refreshed
            }
            None => {
                if self.entries.len() >= MAX_DEVICE_BINDINGS {
                    self.entries.retain(|_, entry| match entry {
                        BindingEntry::Configured(_) => true,
                        BindingEntry::Observed { observed_at, .. } => {
                            now.saturating_duration_since(*observed_at) < OBSERVED_BINDING_TTL
                        }
                    });
                }
                if self.entries.len() >= MAX_DEVICE_BINDINGS {
                    return ObservationOutcome::RejectedCapacity;
                }
                self.entries.insert(
                    device,
                    BindingEntry::Observed {
                        target,
                        observed_at: now,
                    },
                );
                ObservationOutcome::Inserted
            }
        }
    }

    /// Where a targeted Who-Is for `device` goes: the network its last I-Am
    /// came from while that observation is held, or every network for a
    /// device never heard from.
    pub(super) fn who_is_scope(&self, device: &ObjectIdentifier) -> WhoIsScope {
        match self.entries.get(device) {
            Some(BindingEntry::Observed {
                target: DeviceBindingTarget::Local { .. },
                ..
            }) => WhoIsScope::Local,
            Some(BindingEntry::Observed {
                target: DeviceBindingTarget::Routed { network, .. },
                ..
            }) => WhoIsScope::Remote(*network),
            Some(BindingEntry::Configured(_)) | None => WhoIsScope::Global,
        }
    }

    /// Drop `device`'s observation if it is stale at `now`: a Who-Is to
    /// where it was last seen drew nothing, so its next one goes global. A
    /// configured binding, or an observation an I-Am refreshed, stays.
    pub(super) fn forget_stale(&mut self, device: &ObjectIdentifier, now: Instant) {
        if let Some(BindingEntry::Observed { observed_at, .. }) = self.entries.get(device) {
            if now.saturating_duration_since(*observed_at) >= OBSERVED_BINDING_TTL {
                self.entries.remove(device);
            }
        }
    }

    pub(super) fn resolve_at(
        &self,
        device: &ObjectIdentifier,
        now: Instant,
        is_broadcast: impl Fn(&[u8]) -> bool,
    ) -> DeviceResolution {
        if device.object_type() != ObjectType::DEVICE {
            return DeviceResolution::Invalid;
        }
        let (target, freshness) = match self.entries.get(device) {
            Some(BindingEntry::Configured(target)) => (target, BindingFreshness::Configured),
            Some(BindingEntry::Observed {
                target,
                observed_at,
            }) => {
                if now.saturating_duration_since(*observed_at) >= OBSERVED_BINDING_TTL {
                    return DeviceResolution::Stale;
                }
                (
                    target,
                    BindingFreshness::ObservedUntil(tokio::time::Instant::from_std(
                        *observed_at + OBSERVED_BINDING_TTL,
                    )),
                )
            }
            None => return DeviceResolution::Unknown,
        };
        if !target_is_usable(target, is_broadcast) {
            return DeviceResolution::Invalid;
        }
        match target {
            DeviceBindingTarget::Local { peer_mac } => DeviceResolution::ResolvedLocal {
                peer_mac: peer_mac.clone(),
                freshness,
            },
            DeviceBindingTarget::Routed {
                network,
                final_mac,
                router_mac,
            } => DeviceResolution::ResolvedRouted {
                network: *network,
                final_mac: final_mac.clone(),
                router_mac: router_mac.clone(),
                freshness,
            },
        }
    }
}

fn target_is_usable(target: &DeviceBindingTarget, is_broadcast: impl Fn(&[u8]) -> bool) -> bool {
    match target {
        DeviceBindingTarget::Local { peer_mac } => !peer_mac.is_empty() && !is_broadcast(peer_mac),
        DeviceBindingTarget::Routed {
            network,
            final_mac,
            router_mac,
        } => {
            (1..=0xFFFE).contains(network)
                && !final_mac.is_empty()
                && !router_mac.is_empty()
                && !is_broadcast(router_mac)
        }
    }
}

/// Snapshot only services that can submit a tracked command, before the
/// database lock. `local_network` is this network's own number as read for
/// the request.
pub(super) async fn snapshot_command_origin(
    service: ConfirmedServiceChoice,
    immediate: &[u8],
    routed: Option<&NpduAddress>,
    local_network: Option<u16>,
    bindings: &Arc<RwLock<DeviceBindingTable>>,
    transactions: &Arc<NotificationTransactions>,
) -> Option<bacnet_objects::command_source::CommandOrigin> {
    if !matches!(
        service,
        ConfirmedServiceChoice::WRITE_PROPERTY
            | ConfirmedServiceChoice::WRITE_PROPERTY_MULTIPLE
            | ConfirmedServiceChoice::CREATE_OBJECT
    ) {
        return None;
    }
    Some(
        bindings
            .read()
            .await
            .command_origin(immediate, routed, local_network, |mac| {
                transactions
                    .audit_routes
                    .get()
                    .is_some_and(|routes| routes.is_broadcast(mac))
            }),
    )
}
