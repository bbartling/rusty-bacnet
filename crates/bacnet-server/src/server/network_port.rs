//! Explicit single NORMAL B/IP port admission and cancellation-owned startup cleanup.
use super::*;
use bacnet_network::layer::ReceivedApdu;

impl<T: TransportPort + 'static> ServerBuilder<T> {
    /// Select the concrete built-in Network Port for this owned NORMAL B/IP link.
    /// The object must already describe the concrete interface and configured UDP
    /// port (zero is allowed). Startup validates then publishes the actual bind.
    pub fn registered_network_port(mut self, oid: ObjectIdentifier) -> Self {
        self.config.registered_network_port = Some(oid);
        self
    }
}
impl BipServerBuilder {
    /// Select the built-in Network Port that represents this owned NORMAL B/IP link.
    pub fn registered_network_port(mut self, oid: ObjectIdentifier) -> Self {
        self.config.registered_network_port = Some(oid);
        self
    }
}

pub(super) fn prepare<T: TransportPort>(
    db: &mut ObjectDatabase,
    transport: &mut T,
    oid: Option<ObjectIdentifier>,
) -> Result<(), Error> {
    let Some(oid) = oid else {
        return Ok(());
    };
    let address = transport
        .normal_bip_endpoint()
        .ok_or_else(|| Error::Encoding("registered port requires NORMAL B/IP".into()))?;
    let ip = *address.ip();
    if ip.is_unspecified()
        || ip.is_multicast()
        || ip.is_broadcast()
        || transport
            .bip_broadcast_endpoint()
            .is_some_and(|broadcast| *broadcast.ip() == ip)
    {
        return Err(Error::Encoding(
            "registered B/IP requires a concrete unicast interface".into(),
        ));
    }
    let (_, lease) = db.reserve_bip_port_internal(oid, ip.octets(), address.port())?;
    transport.retain_network_port_lease_internal(lease)
}

pub(super) fn publish<T: TransportPort + 'static>(
    db: &mut ObjectDatabase,
    network: &NetworkLayer<T>,
    oid: Option<ObjectIdentifier>,
) -> Result<(), Error> {
    let Some(oid) = oid else {
        return Ok(());
    };
    let address = network
        .transport()
        .normal_bip_endpoint()
        .ok_or_else(|| Error::Encoding("registered B/IP mode changed during bind".into()))?;
    db.publish_bip_port_internal(
        oid,
        address.ip().octets(),
        address.port(),
        network.transport().max_apdu_length() as u32,
    )
}

/// Failed/cancelled startup still owns cleanup. Capturing the runtime at creation
/// lets Drop transfer the network even when its caller drops the future elsewhere.
pub(super) struct StartingNetwork<T: TransportPort + 'static> {
    network: Option<NetworkLayer<T>>,
    runtime: tokio::runtime::Handle,
}
impl<T: TransportPort + 'static> StartingNetwork<T> {
    pub(super) fn new(transport: T) -> Self {
        Self {
            network: Some(NetworkLayer::new(transport)),
            runtime: tokio::runtime::Handle::current(),
        }
    }
    pub(super) fn from_network(network: NetworkLayer<T>) -> Self {
        Self {
            network: Some(network),
            runtime: tokio::runtime::Handle::current(),
        }
    }
    pub(super) fn network(&mut self) -> &mut NetworkLayer<T> {
        self.network.as_mut().expect("startup network owned")
    }
    pub(super) fn finish(mut self) -> NetworkLayer<T> {
        self.network.take().expect("startup network owned")
    }
    pub(super) async fn cleanup(mut self) -> Result<(), Error> {
        let mut network = self.network.take().expect("startup network owned");
        self.runtime
            .spawn(async move { network.stop().await })
            .await
            .map_err(|error| Error::Encoding(format!("startup cleanup failed: {error}")))?
    }
}
impl<T: TransportPort + 'static> Drop for StartingNetwork<T> {
    fn drop(&mut self) {
        if let Some(mut network) = self.network.take() {
            self.runtime.spawn(async move {
                if let Err(error) = network.stop().await {
                    tracing::warn!(%error, "cancelled startup cleanup failed");
                }
            });
        }
    }
}

/// Bind, validate the selected port and finalize Audit routes under one cleanup owner.
pub(super) async fn start<T: TransportPort + 'static>(
    db: &mut ObjectDatabase,
    config: &ServerConfig,
    mut transport: T,
    audit_routes: super::audit_recipient_routes::AuditRoutes,
) -> Result<
    (
        NetworkLayer<T>,
        mpsc::Receiver<ReceivedApdu>,
        Arc<super::audit_recipient_routes::AuditRoutes>,
    ),
    Error,
> {
    prepare(db, &mut transport, config.registered_network_port)?;
    let mut starting = StartingNetwork::new(transport);
    let started = async {
        let apdu_rx = starting.network().start().await?;
        publish(db, starting.network(), config.registered_network_port)?;
        let routes = audit_routes.finish(db, config, starting.network()).await?;
        Ok::<_, Error>((apdu_rx, routes))
    }
    .await;
    match started {
        Ok((apdu_rx, routes)) => Ok((starting.finish(), apdu_rx, routes)),
        Err(error) => {
            starting.cleanup().await?;
            Err(error)
        }
    }
}
