//! Immutable target routing facts captured before shared runtime ownership.
use super::event_recipient_route::{ConfirmedRecipientRoute, RecipientRoute};
use super::*;
use bacnet_network::network_number::LocalNetworkNumber;
use bacnet_types::constructed::{BACnetAddress, BACnetRecipient};

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
    /// binding's final MAC with no DNET, and is answered from there. An
    /// Address recipient naming that number is local the same way (#1460),
    /// as a Notification Class recipient's is: it resolves as network zero
    /// would. While the number is unknown, such an Address names a routed
    /// station, and target Audit routes no Address off this link, so it has
    /// no route ([`Self::awaits_local_number`]).
    pub(super) fn resolve(
        &self,
        recipient: &BACnetRecipient,
    ) -> Option<Arc<ConfirmedRecipientRoute>> {
        let is_broadcast = |mac: &[u8]| self.is_broadcast(mac);
        match recipient {
            BACnetRecipient::Device(device) => {
                let route = self
                    .devices
                    .get(device)?
                    .clone()
                    .localize(self.local_network.get(), is_broadcast)
                    .into_confirmed()?;
                let next_hop = local_next_hop(&route)?;
                (!self.is_broadcast(next_hop)).then(|| Arc::new(route))
            }
            BACnetRecipient::Address(address) => {
                self.bip_broadcast?;
                let RecipientRoute::LocalUnicast(mac) =
                    RecipientRoute::resolve_address(address, is_broadcast)
                        .localize(self.local_network.get(), is_broadcast)
                else {
                    return None;
                };
                if !valid_bip_audit_address(&BACnetAddress {
                    network_number: 0,
                    mac_address: mac.clone(),
                }) {
                    return None;
                }
                RecipientRoute::LocalUnicast(mac)
                    .into_confirmed()
                    .map(Arc::new)
            }
        }
    }

    /// Whether `recipient` is an Address on a network numbered 1 to 65534
    /// that is not this network's number in force, with a MAC this runtime
    /// could send to: no route now, but one whenever that number is this
    /// network's (#1460, #1461). One provisioned so starts unresolved, as a
    /// Device whose binding has no route does; a server without a
    /// registered port learns its number only after it starts. One the
    /// number moved away from no longer holds up a recipient change: it gets
    /// no copy of the change record, since nothing reaches it.
    pub(super) fn awaits_local_number(&self, recipient: &BACnetRecipient) -> bool {
        let BACnetRecipient::Address(address) = recipient else {
            return false;
        };
        self.bip_broadcast.is_some()
            && (1..=0xFFFE).contains(&address.network_number)
            && Some(address.network_number) != self.local_network.get()
            && !self.is_broadcast(&address.mac_address)
            && valid_bip_audit_address(&BACnetAddress {
                network_number: 0,
                mac_address: address.mac_address.clone(),
            })
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
