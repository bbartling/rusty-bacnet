use std::net::{Ipv6Addr, SocketAddrV6};
use std::sync::Arc;
use std::time::Duration;

use bacnet_types::error::Error;
use bytes::BytesMut;
use tokio::sync::mpsc;
use tokio::task::JoinHandle;
use tracing::{debug, warn};

use crate::port::{ReceivedNpdu, TransportPort};

use super::ingress::{is_local_unicast_delivery, LocalBinding};
use super::receive::Receiver;
use super::socket::Bip6Socket;
use super::vmac_table::{derive_vmac_from_device_instance, generate_random_vmac, VmacTable};
use super::{
    decode_bvlc6, encode_address_resolution, encode_address_resolution_ack, encode_bvlc6,
    encode_bvlc6_original_broadcast, encode_bvlc6_original_unicast, Bip6Vmac, Bvlc6Function,
    BVLC6_HEADER_LENGTH, BVLC6_UNICAST_HEADER_LENGTH, MAX_VMAC_RETRIES,
};

/// BACnet/IPv6 multicast group (link-local): FF02::BAC0.
pub const BACNET_IPV6_MULTICAST_LINK_LOCAL: Ipv6Addr =
    Ipv6Addr::new(0xFF02, 0, 0, 0, 0, 0, 0, 0xBAC0);

/// BACnet/IPv6 multicast group (site-local): FF05::BAC0.
pub const BACNET_IPV6_MULTICAST_SITE_LOCAL: Ipv6Addr =
    Ipv6Addr::new(0xFF05, 0, 0, 0, 0, 0, 0, 0xBAC0);

/// BACnet/IPv6 multicast group (organization-local): FF08::BAC0.
pub const BACNET_IPV6_MULTICAST_ORG_LOCAL: Ipv6Addr =
    Ipv6Addr::new(0xFF08, 0, 0, 0, 0, 0, 0, 0xBAC0);

/// BACnet/IPv6 multicast group -- alias for link-local (backward compatibility).
pub const BACNET_IPV6_MULTICAST: Ipv6Addr = BACNET_IPV6_MULTICAST_LINK_LOCAL;

/// Default BACnet/IPv6 port (same as BIP: 0xBAC0 = 47808).
pub const DEFAULT_BACNET6_PORT: u16 = 0xBAC0;

/// Encode an IPv6 address + port into an 18-byte MAC.
///
/// Format: `[IPv6 address (16 bytes)][port (2 bytes big-endian)]`
pub fn encode_bip6_mac(ip: Ipv6Addr, port: u16) -> [u8; 18] {
    let mut mac = [0u8; 18];
    mac[..16].copy_from_slice(&ip.octets());
    mac[16..18].copy_from_slice(&port.to_be_bytes());
    mac
}

/// Decode an 18-byte MAC into an IPv6 address + port.
pub fn decode_bip6_mac(mac: &[u8]) -> Result<(Ipv6Addr, u16), Error> {
    if mac.len() != 18 {
        return Err(Error::decoding(
            0,
            format!("BIP6 MAC must be 18 bytes, got {}", mac.len()),
        ));
    }
    let mut ip_bytes = [0u8; 16];
    ip_bytes.copy_from_slice(&mac[..16]);
    let ip = Ipv6Addr::from(ip_bytes);
    let port = u16::from_be_bytes([mac[16], mac[17]]);
    Ok((ip, port))
}

/// BACnet/IPv6 transport over UDP (Annex U).
pub struct Bip6Transport {
    interface: Ipv6Addr,
    port: u16,
    device_instance: Option<u32>,
    local_mac: [u8; 18],
    pub(super) source_vmac: Bip6Vmac,
    pub(super) socket: Option<Arc<Bip6Socket>>,
    recv_task: Option<JoinHandle<()>>,
    /// VMAC address table (Clause U.5).
    pub(super) vmac_table: VmacTable,
    /// Broadcast scope for send_broadcast.
    broadcast_scope: Bip6BroadcastScope,
    /// Foreign device BBMD configuration (optional).
    foreign_device: Option<Bip6ForeignDeviceConfig>,
    /// Foreign device re-registration task handle.
    registration_task: Option<JoinHandle<()>>,
}

/// Configuration for BIPv6 foreign device registration.
#[derive(Debug, Clone)]
pub struct Bip6ForeignDeviceConfig {
    /// BBMD IPv6 address to register with.
    pub bbmd_ip: Ipv6Addr,
    /// BBMD port.
    pub bbmd_port: u16,
    /// Time-to-live in seconds.
    pub ttl: u16,
}

/// IPv6 multicast scope for BACnet broadcasts.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Bip6BroadcastScope {
    /// FF02::BAC0 — link-local (single link only)
    LinkLocal,
    /// FF05::BAC0 — site-local (building/campus, default)
    SiteLocal,
    /// FF08::BAC0 — organization-local
    OrganizationLocal,
}

impl Bip6BroadcastScope {
    fn multicast_addr(&self) -> Ipv6Addr {
        match self {
            Self::LinkLocal => BACNET_IPV6_MULTICAST_LINK_LOCAL,
            Self::SiteLocal => BACNET_IPV6_MULTICAST_SITE_LOCAL,
            Self::OrganizationLocal => BACNET_IPV6_MULTICAST_ORG_LOCAL,
        }
    }
}

impl Bip6Transport {
    /// Create a new BACnet/IPv6 transport.
    ///
    /// - `interface`: Concrete local IPv6 address selecting its unique usable
    ///   interface, or `::` for unambiguous automatic selection. Automatic mode
    ///   prefers a non-loopback link and a unique non-link-local address on it;
    ///   ambiguity is an error. Loopback is node-local only. Normal operation
    ///   retains the selected source/index on a wildcard receive socket.
    ///   Foreign `::` instead selects a source usable for the configured BBMD.
    /// - `port`: UDP port (default 47808 / 0xBAC0)
    /// - `device_instance`: If `Some(id)`, derive the 3-byte VMAC from the
    ///   valid 22-bit device instance (per Clause H.7.2). Otherwise an
    ///   OS-random Random Device Instance VMAC is generated at startup.
    pub fn new(interface: Ipv6Addr, port: u16, device_instance: Option<u32>) -> Self {
        Self {
            interface,
            port,
            device_instance,
            local_mac: [0; 18],
            source_vmac: [0; 3],
            socket: None,
            recv_task: None,
            vmac_table: VmacTable::new(),
            broadcast_scope: Bip6BroadcastScope::SiteLocal,
            foreign_device: None,
            registration_task: None,
        }
    }

    /// Set the broadcast scope for send_broadcast.
    pub fn set_broadcast_scope(&mut self, scope: Bip6BroadcastScope) {
        self.broadcast_scope = scope;
    }

    /// Configure this transport as a foreign device.
    ///
    /// Foreign `::` derives a concrete source from the route to the BBMD and
    /// binds the production socket to it. An explicit address is retained.
    /// Foreign startup does not require normal-mode multicast membership.
    /// A foreign device must also have a configured Device instance. Random
    /// VMAC startup is rejected until BBMD-assisted collision resolution is
    /// implemented.
    /// Must be called before `start()`.
    pub fn register_as_foreign_device(&mut self, config: Bip6ForeignDeviceConfig) {
        self.foreign_device = Some(config);
    }
}

/// Derive a 3-byte VMAC from a 22-bit device instance (Clause H.7.2).
/// Send a Register-Foreign-Device message (Clause U.4.5).
async fn send_register_foreign_device_v6(
    socket: &Bip6Socket,
    bbmd_addr: SocketAddrV6,
    ttl: u16,
    source_vmac: &Bip6Vmac,
) {
    let mut buf = BytesMut::with_capacity(BVLC6_HEADER_LENGTH + 2);
    if let Err(e) = encode_bvlc6(
        &mut buf,
        Bvlc6Function::RegisterForeignDevice,
        source_vmac,
        &ttl.to_be_bytes(),
    ) {
        warn!(error = %e, "BIP6: failed to encode Register-Foreign-Device");
        return;
    }
    if let Err(e) = socket.send_to(&buf, bbmd_addr).await {
        warn!(error = %e, "BIP6: failed to send Register-Foreign-Device");
    } else {
        debug!(bbmd = %bbmd_addr, ttl = ttl, "BIP6: sent Register-Foreign-Device");
    }
}

impl TransportPort for Bip6Transport {
    fn supports_local_nonrouter_number_controls(&self) -> bool {
        true
    }

    async fn start(&mut self) -> Result<mpsc::Receiver<ReceivedNpdu>, Error> {
        if self.recv_task.is_some() {
            return Err(Error::Transport(std::io::Error::new(
                std::io::ErrorKind::AlreadyExists,
                "BIP6 transport already started",
            )));
        }
        if self.device_instance.is_some_and(|id| id > 0x3F_FFFF) {
            return Err(Error::Encoding(
                "BACnet Device instance must be in 0..=4194303".to_string(),
            ));
        }
        if self.foreign_device.is_some() && self.device_instance.is_none() {
            return Err(Error::Transport(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "BIP6 foreign devices require a configured Device instance until BBMD-assisted random-VMAC resolution is implemented",
            )));
        }

        // Resolve and prepare privately. No identity, port, VMAC or socket is
        // published until joins and the required collision exchange succeed.
        let foreign = self
            .foreign_device
            .as_ref()
            .map(|fd| SocketAddrV6::new(fd.bbmd_ip, fd.bbmd_port, 0, 0));
        let socket = Arc::new(
            Bip6Socket::bind(self.interface, self.port, foreign)
                .await
                .map_err(Error::Transport)?,
        );
        let local_port = socket.local_port().map_err(Error::Transport)?;
        let local_ip = socket
            .selection
            .map(|link| link.address)
            .unwrap_or(*socket.local_address().map_err(Error::Transport)?.ip());
        let wildcard_bind = false;
        let local_unicast_ips = vec![local_ip];
        let local_mac = encode_bip6_mac(local_ip, local_port);
        let mut source_vmac = if let Some(id) = self.device_instance {
            derive_vmac_from_device_instance(id)
        } else {
            generate_random_vmac()?
        };
        let if_index = socket.selection.map_or(0, |link| link.index);
        let collision_probe_required = self.device_instance.is_none();
        let collision_group = self.broadcast_scope.multicast_addr();

        // VMAC collision detection and resolution
        if self.foreign_device.is_none() {
            let multicast_dest = SocketAddrV6::new(collision_group, local_port, 0, if_index);
            let mut check_buf = vec![0u8; 64];

            for attempt in 0..=MAX_VMAC_RETRIES {
                let ar_msg = encode_address_resolution(&source_vmac, &source_vmac);
                if let Err(error) = socket.send_to(&ar_msg, multicast_dest).await {
                    if collision_probe_required {
                        return Err(Error::Transport(error));
                    }
                    debug!(error = %error, "Configured-VMAC collision probe send failed");
                }

                let mut collision = false;
                let deadline = tokio::time::Instant::now() + Duration::from_millis(200);
                loop {
                    match tokio::time::timeout_at(deadline, socket.recv_from(&mut check_buf)).await
                    {
                        Ok(Ok(received)) => {
                            if let Ok(frame) = decode_bvlc6(&check_buf[..received.len]) {
                                let is_self_loop = matches!(
                                    received.peer,
                                    std::net::SocketAddr::V6(peer)
                                        if peer.port() == local_port
                                            && (*peer.ip() == local_ip
                                                || local_unicast_ips.contains(peer.ip()))
                                );
                                if frame.function == Bvlc6Function::AddressResolution
                                    && frame.destination_vmac == Some(source_vmac)
                                    && matches!(received.destination, std::net::IpAddr::V6(ip) if ip == collision_group)
                                    && received.os_group_delivery != Some(false)
                                    && !is_self_loop
                                {
                                    let ack = encode_address_resolution_ack(
                                        &source_vmac,
                                        &frame.source_vmac,
                                    );
                                    if let Err(error) = socket.send_to(&ack, received.peer).await {
                                        if collision_probe_required {
                                            return Err(Error::Transport(error));
                                        }
                                        debug!(error = %error, "Configured-VMAC AR-Ack send failed");
                                    }
                                    if frame.source_vmac == source_vmac {
                                        collision = true;
                                        break;
                                    }
                                }
                                // AR-ACK from another node using our VMAC.
                                if frame.function == Bvlc6Function::AddressResolutionAck
                                    && frame.source_vmac == source_vmac
                                    && is_local_unicast_delivery(
                                        received.destination,
                                        frame.destination_vmac,
                                        &LocalBinding {
                                            ip: local_ip,
                                            vmac: source_vmac,
                                            unicast_ips: &local_unicast_ips,
                                            wildcard_bind,
                                        },
                                        received.os_group_delivery,
                                    )
                                {
                                    collision = true;
                                    break;
                                }
                            }
                        }
                        Ok(Err(e)) if e.kind() == std::io::ErrorKind::InvalidData => {
                            debug!(error = %e, "Error during VMAC collision check");
                            continue;
                        }
                        Ok(Err(e)) => {
                            if collision_probe_required {
                                return Err(Error::Transport(e));
                            }
                            debug!(error = %e, "Configured-VMAC collision probe receive failed");
                            break;
                        }
                        Err(_) => break, // timeout elapsed — no collision
                    }
                }

                if !collision {
                    break;
                }

                if self.device_instance.is_some() {
                    return Err(Error::Transport(std::io::Error::new(
                        std::io::ErrorKind::AddrInUse,
                        "configured BACnet Device instance VMAC is already in use",
                    )));
                }

                if attempt < MAX_VMAC_RETRIES {
                    let old_vmac = source_vmac;
                    source_vmac = generate_random_vmac()?;
                    warn!(
                        old_vmac = ?old_vmac,
                        new_vmac = ?source_vmac,
                        attempt = attempt + 1,
                        max_retries = MAX_VMAC_RETRIES,
                        "BIP6 VMAC collision detected, re-deriving new VMAC"
                    );
                } else {
                    return Err(Error::Transport(std::io::Error::new(
                        std::io::ErrorKind::AddrInUse,
                        format!(
                            "random BIP6 VMAC collision persists after {MAX_VMAC_RETRIES} retries"
                        ),
                    )));
                }
            }
        }

        // Do the only foreign-device startup I/O before spawning owned tasks,
        // so cancellation cannot orphan an unpublished receive worker.
        if let Some(fd) = &self.foreign_device {
            send_register_foreign_device_v6(
                &socket,
                SocketAddrV6::new(fd.bbmd_ip, fd.bbmd_port, 0, 0),
                fd.ttl,
                &source_vmac,
            )
            .await;
        }

        /// NPDU receive channel capacity for high-throughput UDP transports.
        const NPDU_CHANNEL_CAPACITY: usize = 256;

        let (tx, rx) = mpsc::channel(NPDU_CHANNEL_CAPACITY);

        let receiver = Receiver {
            socket: Arc::clone(&socket),
            tx,
            local_mac,
            vmac: source_vmac,
            local_ip,
            unicast_ips: local_unicast_ips,
            wildcard_bind,
            foreign_bbmd: self
                .foreign_device
                .as_ref()
                .map(|fd| (fd.bbmd_ip, fd.bbmd_port)),
            vmac_table: self.vmac_table.clone(),
        };
        let recv_task = tokio::spawn(receiver.run());

        self.local_mac = local_mac;
        self.source_vmac = source_vmac;
        self.recv_task = Some(recv_task);
        self.socket = Some(Arc::clone(&socket));

        // Start foreign device registration if configured
        if let Some(fd) = &self.foreign_device {
            let bbmd_addr = SocketAddrV6::new(fd.bbmd_ip, fd.bbmd_port, 0, 0);
            let ttl = fd.ttl;
            let sock = Arc::clone(&socket);
            let source_vmac = self.source_vmac;

            // Re-register at TTL/2 interval
            let interval = std::time::Duration::from_secs(((ttl as u64) / 2).max(30));
            let reg_task = tokio::spawn(async move {
                let mut ticker = tokio::time::interval(interval);
                ticker.tick().await; // Skip first immediate tick
                loop {
                    ticker.tick().await;
                    send_register_foreign_device_v6(&sock, bbmd_addr, ttl, &source_vmac).await;
                }
            });
            self.registration_task = Some(reg_task);
        }

        Ok(rx)
    }

    async fn stop(&mut self) -> Result<(), Error> {
        if let Some(task) = self.registration_task.take() {
            task.abort();
            let _ = task.await;
        }
        if let Some(task) = self.recv_task.take() {
            task.abort();
            let _ = task.await;
        }
        self.socket = None;
        self.local_mac = [0; 18];
        self.source_vmac = [0; 3];
        self.vmac_table = VmacTable::new();
        Ok(())
    }

    async fn send_unicast(&self, npdu: &[u8], mac: &[u8]) -> Result<(), Error> {
        let socket = self.socket.as_ref().ok_or_else(|| {
            Error::Transport(std::io::Error::new(
                std::io::ErrorKind::NotConnected,
                "Transport not started",
            ))
        })?;

        let (ip, port) = decode_bip6_mac(mac)?;
        let mut buf = BytesMut::with_capacity(BVLC6_UNICAST_HEADER_LENGTH + npdu.len());
        // Original-Unicast requires the destination's actual VMAC. The
        // network MAC contains only IPv6+port, so use the latest learned
        // mapping both for that VMAC and for the exact scoped endpoint.
        let (dest_vmac, dest) =
            self.vmac_table
                .resolve_by_addr(ip, port)
                .await
                .ok_or_else(|| {
                    Error::Transport(std::io::Error::new(
                        std::io::ErrorKind::AddrNotAvailable,
                        "BIP6 destination VMAC is unknown; receive a frame from the peer first",
                    ))
                })?;
        encode_bvlc6_original_unicast(&mut buf, &self.source_vmac, &dest_vmac, npdu)?;

        socket.send_to(&buf, dest).await.map_err(Error::Transport)?;

        Ok(())
    }

    async fn send_broadcast(&self, npdu: &[u8]) -> Result<(), Error> {
        let socket = self.socket.as_ref().ok_or_else(|| {
            Error::Transport(std::io::Error::new(
                std::io::ErrorKind::NotConnected,
                "Transport not started",
            ))
        })?;

        let source_vmac = self.source_vmac;

        // In foreign device mode, use Distribute-Broadcast-To-Network via BBMD
        if let Some(fd) = &self.foreign_device {
            let bbmd_addr = SocketAddrV6::new(fd.bbmd_ip, fd.bbmd_port, 0, 0);
            let mut buf = BytesMut::with_capacity(BVLC6_HEADER_LENGTH + npdu.len());
            encode_bvlc6(
                &mut buf,
                Bvlc6Function::DistributeBroadcastToNetwork,
                &source_vmac,
                npdu,
            )?;
            socket
                .send_to(&buf, bbmd_addr)
                .await
                .map_err(Error::Transport)?;
            return Ok(());
        }

        let dest = SocketAddrV6::new(
            self.broadcast_scope.multicast_addr(),
            socket.local_port().map_err(Error::Transport)?,
            0,
            0,
        );
        let mut buf = BytesMut::with_capacity(BVLC6_HEADER_LENGTH + npdu.len());
        encode_bvlc6_original_broadcast(&mut buf, &source_vmac, npdu)?;

        socket.send_to(&buf, dest).await.map_err(Error::Transport)?;

        Ok(())
    }

    fn local_receive_apdu_capacity(&self) -> u16 {
        1476
    }

    fn local_mac(&self) -> &[u8] {
        &self.local_mac
    }

    fn is_broadcast_mac(&self, mac: &[u8]) -> bool {
        // A B/IPv6 MAC is 16 address octets + 2 port octets. The broadcast
        // spelling is any of the well-known BACnet multicast groups
        // (Clause U.4); the port octets do not decide broadcast-ness.
        if mac.len() != 18 {
            return false;
        }
        [
            BACNET_IPV6_MULTICAST_LINK_LOCAL,
            BACNET_IPV6_MULTICAST_SITE_LOCAL,
            BACNET_IPV6_MULTICAST_ORG_LOCAL,
        ]
        .iter()
        .any(|group| mac[..16] == group.octets())
    }
}

impl Drop for Bip6Transport {
    fn drop(&mut self) {
        // The tasks own socket clones. Abort them so dropping the transport
        // cannot detach a receive/registration lifetime from its owner.
        if let Some(task) = self.registration_task.take() {
            task.abort();
        }
        if let Some(task) = self.recv_task.take() {
            task.abort();
        }
    }
}
