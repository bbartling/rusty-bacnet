//! Immutable target routing facts captured before shared runtime ownership.
use super::event_recipient_route::{ConfirmedRecipientRoute, RecipientRoute};
use super::*;
use bacnet_network::network_number::LocalNetworkNumber;
use bacnet_types::constructed::BACnetRecipient;

#[derive(Default)]
pub(super) struct AuditRoutes {
    /// Each configured Device binding's route, as configured.
    devices: HashMap<ObjectIdentifier, RecipientRoute>,
    bip_broadcast: Option<std::net::SocketAddrV4>,
    configured_broadcasts: std::collections::HashSet<MacAddr>,
    /// The started link's local network number, read at each resolution so
    /// a number published after startup applies to the next notification
    /// (#1358). Unknown until [`Self::finish`].
    local_network: LocalNetworkNumber,
}

impl AuditRoutes {
    fn capture<T: TransportPort>(bindings: &DeviceBindingTable, transport: &T) -> Self {
        Self {
            devices: bindings
                .configured_resolutions()
                .map(|(device, resolution)| {
                    (device, RecipientRoute::from_device_resolution(resolution))
                })
                .filter(|(_, route)| next_hop(route).is_some())
                .collect(),
            bip_broadcast: transport.bip_broadcast_endpoint(),
            ..Self::default()
        }
    }

    pub(super) fn prepare<T: TransportPort>(
        db: &mut ObjectDatabase,
        config: &ServerConfig,
        bindings: &DeviceBindingTable,
        transport: &T,
    ) -> Result<Self, Error> {
        let routes = if config.audit_reporters.is_some() {
            Self::capture(bindings, transport)
        } else {
            Self::default()
        };
        super::audit_recipient::validate(db, config, &routes)?;
        Ok(routes)
    }

    /// Finalize link facts and configured next hops after start, before shared ownership.
    pub(super) async fn finish<T: TransportPort + 'static>(
        mut self,
        db: &mut ObjectDatabase,
        config: &ServerConfig,
        network: &mut NetworkLayer<T>,
    ) -> Result<Arc<Self>, Error> {
        if config.audit_reporters.is_some() {
            self.bip_broadcast = network.transport().bip_broadcast_endpoint();
            self.local_network = network.local_network_number().clone();
            // A generic link can learn its broadcast identity during start.
            // Invoke caller code once here, never during target production or
            // mutation under shared DB/admission locks. Invalid Device routes
            // become unresolved rather than rejecting the whole server.
            let transport = network.transport();
            let broadcasts = &mut self.configured_broadcasts;
            self.devices.retain(|_, route| {
                // A routed binding's final MAC is its next hop once the route
                // is taken as local, so its broadcast fact is kept too.
                if let RecipientRoute::BoundRoutedUnicast { mac, .. } = route {
                    if transport.is_broadcast_mac(mac) {
                        broadcasts.insert(mac.clone());
                    }
                }
                next_hop(route).is_some_and(|mac| {
                    if transport.is_broadcast_mac(mac) {
                        // Retain the fact as well as pruning delivery: source
                        // correlation uses the same post-start eligibility.
                        broadcasts.insert(mac.clone());
                        false
                    } else {
                        true
                    }
                })
            });
            if let Err(error) = super::audit_recipient::validate(db, config, &self) {
                let _ = network.stop().await;
                return Err(error);
            }
        }
        Ok(Arc::new(self))
    }

    pub(super) fn is_broadcast(&self, mac: &[u8]) -> bool {
        self.configured_broadcasts.contains(mac)
            || self.bip_broadcast.is_some_and(|broadcast| {
                mac.len() == 6
                    && mac[..4] == broadcast.ip().octets()
                    && mac[4..] == broadcast.port().to_be_bytes()
            })
    }

    /// Pure lookup/byte validation: no transport, caller code, locks or clocks.
    /// A Device binding routed through this network's own number, read here
    /// with one atomic load, is the local route it is (#1358): it goes to the
    /// binding's final MAC with no DNET, and is answered from there.
    pub(super) fn resolve(
        &self,
        recipient: &BACnetRecipient,
    ) -> Option<Arc<ConfirmedRecipientRoute>> {
        match recipient {
            BACnetRecipient::Device(device) => {
                let route = self
                    .devices
                    .get(device)?
                    .clone()
                    .localize(self.local_network.get(), |mac| self.is_broadcast(mac))
                    .into_confirmed()?;
                let next_hop = local_next_hop(&route)?;
                (!self.is_broadcast(next_hop)).then(|| Arc::new(route))
            }
            BACnetRecipient::Address(address) => {
                self.bip_broadcast?;
                if !valid_bip_audit_address(address) || self.is_broadcast(&address.mac_address) {
                    return None;
                }
                RecipientRoute::LocalUnicast(address.mac_address.clone())
                    .into_confirmed()
                    .map(Arc::new)
            }
        }
    }
}

/// The local data-link destination of a configured binding's route.
fn next_hop(route: &RecipientRoute) -> Option<&MacAddr> {
    match route {
        RecipientRoute::BoundLocalUnicast { mac, .. } => Some(mac),
        RecipientRoute::BoundRoutedUnicast { router, .. } => Some(router),
        _ => None,
    }
}

fn local_next_hop(route: &ConfirmedRecipientRoute) -> Option<&MacAddr> {
    route.local_target.as_ref().or_else(|| {
        route
            .remote
            .as_ref()
            .and_then(|(_, _, router)| router.as_ref())
    })
}
