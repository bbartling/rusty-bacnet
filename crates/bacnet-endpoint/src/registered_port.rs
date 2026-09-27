//! One explicit registered B/IP association; declaration is not registration.
use super::*;
use std::net::SocketAddrV4;

impl<T: TransportPort + 'static> EndpointSession<T> {
    /// Select one existing built-in Network Port for the owned NORMAL B/IP link.
    /// Startup requires a matching concrete interface, identity entry and database
    /// snapshot. It publishes actual IP/UDP/MAC before exposing responder roles.
    pub fn with_registered_network_port(mut self, oid: ObjectIdentifier) -> Self {
        self.assert_configurable();
        self.registered_network_port = Some(oid);
        self
    }

    pub(super) async fn prepare_registered_port(&mut self) -> Result<(), Error> {
        let Some(oid) = self.registered_network_port else {
            return Ok(());
        };
        let ingress = self
            .ingress
            .as_mut()
            .ok_or_else(|| invalid("missing ingress"))?;
        let address = ingress
            .normal_bip_endpoint()
            .ok_or_else(|| invalid("registration requires NORMAL B/IP"))?;
        let ip = *address.ip();
        if ip.is_unspecified()
            || ip.is_multicast()
            || ip.is_broadcast()
            || ingress
                .bip_broadcast_endpoint()
                .is_some_and(|broadcast| *broadcast.ip() == ip)
        {
            return Err(invalid(
                "registered B/IP requires a concrete unicast interface",
            ));
        }
        let db = self
            .database
            .as_ref()
            .ok_or_else(|| invalid("registered port requires database"))?;
        let mut db = db.write().await;
        // Validate identity before reservation so a rejected configuration has no effects.
        let configured = db
            .configured_bip_port_internal(&oid)
            .ok_or_else(|| invalid("selected built-in B/IP port missing"))?;
        if let Some(identity) = &self.identity {
            identity.validate_registered_bip(oid, &configured)?;
        }
        let (_, lease) = db.reserve_bip_port_internal(oid, ip.octets(), address.port())?;
        self.registered_port_lease = Arc::downgrade(&lease);
        ingress.retain_network_port_lease_internal(lease)
    }

    pub(super) async fn publish_registered_port(
        &mut self,
        actual: Option<(SocketAddrV4, u16)>,
    ) -> Result<(), Error> {
        let Some(oid) = self.registered_network_port else {
            return Ok(());
        };
        let (address, capacity) =
            actual.ok_or_else(|| invalid("registered B/IP mode changed during bind"))?;
        let mut db = self
            .database
            .as_ref()
            .expect("validated database")
            .write()
            .await;
        db.publish_bip_port_internal(oid, address.ip().octets(), address.port(), capacity as u32)?;
        if let Some(identity) = &mut self.identity {
            identity.publish_registered_bip(oid, address);
        }
        Ok(())
    }
}
fn invalid(message: &str) -> Error {
    Error::Encoding(message.into())
}
