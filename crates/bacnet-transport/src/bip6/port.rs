use std::collections::hash_map::RandomState;
use std::hash::{BuildHasher, Hasher};
use std::net::{IpAddr, Ipv6Addr, SocketAddrV6};
use std::sync::Arc;
use std::time::Duration;

use bacnet_types::error::Error;
use bacnet_types::MacAddr;
use bytes::{Bytes, BytesMut};
use tokio::net::UdpSocket;
use tokio::sync::mpsc;
use tokio::task::JoinHandle;
use tracing::{debug, warn};

use crate::port::{ReceivedNpdu, TransportPort};
use crate::udp_metadata::{DestinationReceiver, IpVersion};

use super::frame::destination_vmac_matches;
use super::vmac_table::VmacTable;
use super::{
    decode_bvlc6, decode_forwarded_npdu_payload, encode_address_resolution_ack, encode_bvlc6,
    encode_bvlc6_original_broadcast, encode_bvlc6_original_unicast,
    encode_virtual_address_resolution, encode_virtual_address_resolution_ack, Bip6Vmac,
    Bvlc6Function, BVLC6_HEADER_LENGTH, BVLC6_UNICAST_HEADER_LENGTH, MAX_VMAC_RETRIES,
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

fn is_bacnet_ipv6_multicast(destination: Ipv6Addr) -> bool {
    matches!(
        destination,
        BACNET_IPV6_MULTICAST_LINK_LOCAL
            | BACNET_IPV6_MULTICAST_SITE_LOCAL
            | BACNET_IPV6_MULTICAST_ORG_LOCAL
    )
}

fn is_local_unicast_delivery(
    destination: IpAddr,
    destination_vmac: Option<Bip6Vmac>,
    local_ip: Ipv6Addr,
    local_vmac: Bip6Vmac,
    os_group_delivery: Option<bool>,
) -> bool {
    destination == IpAddr::V6(local_ip)
        && destination_vmac == Some(local_vmac)
        && os_group_delivery != Some(true)
}

pub(super) fn original_destination_matches(
    function: Bvlc6Function,
    destination: IpAddr,
    destination_vmac: Option<Bip6Vmac>,
    local_ip: Ipv6Addr,
    local_vmac: Bip6Vmac,
    os_group_delivery: Option<bool>,
) -> bool {
    match function {
        Bvlc6Function::OriginalUnicast
        | Bvlc6Function::AddressResolutionAck
        | Bvlc6Function::VirtualAddressResolutionAck => is_local_unicast_delivery(
            destination,
            destination_vmac,
            local_ip,
            local_vmac,
            os_group_delivery,
        ),
        Bvlc6Function::OriginalBroadcast => {
            matches!(destination, IpAddr::V6(ip) if is_bacnet_ipv6_multicast(ip))
                && os_group_delivery != Some(false)
        }
        _ => true,
    }
}

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
    pub(super) socket: Option<Arc<UdpSocket>>,
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
    /// - `interface`: Local IPv6 address to bind (use `::` for all interfaces)
    /// - `port`: UDP port (default 47808 / 0xBAC0)
    /// - `device_instance`: If `Some(id)`, derive the 3-byte VMAC from the
    ///   lower 22 bits of the device instance (per Clause H.7.2). Otherwise the
    ///   VMAC is derived from the local IPv6 address + port.
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
    /// Must be called before `start()`.
    pub fn register_as_foreign_device(&mut self, config: Bip6ForeignDeviceConfig) {
        self.foreign_device = Some(config);
    }
}

/// Derive a 3-byte VMAC from the lower 24 bits of a device instance (Annex U.5).
/// Send a Register-Foreign-Device message (Clause U.4.5).
async fn send_register_foreign_device_v6(
    socket: &UdpSocket,
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

pub(super) fn derive_vmac_from_device_instance(device_instance: u32) -> Bip6Vmac {
    // Mask to 22 bits per Clause H.7.2 (BACnet device instances are 22-bit)
    let masked = device_instance & 0x3FFFFF;
    let bytes = masked.to_be_bytes(); // [b0, b1, b2, b3]
    [bytes[1], bytes[2], bytes[3]]
}

/// Generate a random 3-byte VMAC for collision resolution (Annex U.5).
pub fn generate_random_vmac() -> Bip6Vmac {
    let h = RandomState::new().build_hasher().finish().to_ne_bytes();
    [h[0], h[1], h[2]]
}

/// Derive a 3-byte VMAC by XOR-folding 16-byte IPv6 + 2-byte port.
fn derive_vmac_from_addr(addr: &SocketAddrV6) -> Bip6Vmac {
    let octets = addr.ip().octets();
    let port_bytes = addr.port().to_be_bytes();
    let mut vmac = [0u8; 3];
    for (i, &b) in octets.iter().chain(port_bytes.iter()).enumerate() {
        vmac[i % 3] ^= b;
    }
    vmac
}

/// Resolve the local IPv6 address by connecting a UDP socket to a link-local
/// multicast address and reading back the local address. No packets are sent.
/// Uses ff02::1 (all-nodes link-local) to avoid any external DNS dependency.
fn resolve_local_ipv6() -> Option<Ipv6Addr> {
    let socket = std::net::UdpSocket::bind("[::]:0").ok()?;
    // Connect to link-local all-nodes multicast on BACnet port -- no packets sent.
    match socket.connect("[ff02::1]:47808") {
        Ok(()) => {}
        Err(_) => {
            warn!("Could not resolve local IPv6 address via ff02::1, falling back to localhost");
            return None;
        }
    }
    match socket.local_addr().ok()? {
        std::net::SocketAddr::V6(v6) => Some(*v6.ip()),
        _ => None,
    }
}

/// Best-effort resolution of IPv6 interface index for the given address.
/// Returns `None` if the interface cannot be determined.
#[allow(unsafe_code)]
fn resolve_interface_index(addr: &Ipv6Addr) -> Option<u32> {
    #[cfg(unix)]
    {
        use std::ffi::CStr;

        /// RAII guard for `getifaddrs` that calls `freeifaddrs` on drop.
        struct IfAddrsGuard(*mut libc::ifaddrs);
        impl Drop for IfAddrsGuard {
            fn drop(&mut self) {
                // SAFETY: `self.0` was returned by `getifaddrs` and stored without modification;
                // `freeifaddrs` is the matching deallocator and is called exactly once on drop.
                unsafe { libc::freeifaddrs(self.0) }
            }
        }

        // SAFETY: this block performs the `getifaddrs`/walk/family-dispatch dance. The
        // returned linked list is owned by `_guard` (calls `freeifaddrs` on drop). All
        // pointer dereferences of `cursor`/`ifa.ifa_addr` are gated on null checks; address
        // family bytes are read after confirming `family == AF_INET6`. `CStr::from_ptr`
        // requires NUL-terminated strings, which the kernel guarantees for `ifa_name`.
        unsafe {
            let mut ifaddrs: *mut libc::ifaddrs = std::ptr::null_mut();
            if libc::getifaddrs(&mut ifaddrs) != 0 {
                return None;
            }
            let _guard = IfAddrsGuard(ifaddrs);
            let mut cursor = ifaddrs;
            while !cursor.is_null() {
                let ifa = &*cursor;
                if !ifa.ifa_addr.is_null() {
                    let family = (*ifa.ifa_addr).sa_family as i32;
                    if family == libc::AF_INET6 {
                        let sockaddr6 = &*(ifa.ifa_addr as *const libc::sockaddr_in6);
                        let ifa_ip = Ipv6Addr::from(sockaddr6.sin6_addr.s6_addr);
                        if ifa_ip == *addr {
                            let name = CStr::from_ptr(ifa.ifa_name);
                            let idx = libc::if_nametoindex(name.as_ptr());
                            if idx != 0 {
                                return Some(idx);
                            }
                        }
                    }
                }
                cursor = ifa.ifa_next;
            }
            None
        }
    }
    #[cfg(not(unix))]
    {
        let _ = addr;
        None
    }
}

impl TransportPort for Bip6Transport {
    async fn start(&mut self) -> Result<mpsc::Receiver<ReceivedNpdu>, Error> {
        if self.recv_task.is_some() {
            return Err(Error::Transport(std::io::Error::new(
                std::io::ErrorKind::AlreadyExists,
                "BIP6 transport already started",
            )));
        }

        let socket2_sock = socket2::Socket::new(
            socket2::Domain::IPV6,
            socket2::Type::DGRAM,
            Some(socket2::Protocol::UDP),
        )
        .map_err(Error::Transport)?;

        socket2_sock.set_only_v6(true).map_err(Error::Transport)?;
        socket2_sock
            .set_reuse_address(true)
            .map_err(Error::Transport)?;
        socket2_sock
            .set_nonblocking(true)
            .map_err(Error::Transport)?;
        socket2_sock
            .set_multicast_loop_v6(true)
            .map_err(Error::Transport)?;

        let bind_addr = SocketAddrV6::new(self.interface, self.port, 0, 0);
        socket2_sock
            .bind(&bind_addr.into())
            .map_err(Error::Transport)?;

        let destination_receiver = DestinationReceiver::configure(&socket2_sock, IpVersion::V6)
            .map_err(Error::Transport)?;

        let std_socket: std::net::UdpSocket = socket2_sock.into();
        let socket = UdpSocket::from_std(std_socket).map_err(Error::Transport)?;

        let local_addr = socket.local_addr().map_err(Error::Transport)?;
        let local_port = local_addr.port();
        self.port = local_port;

        let local_ip = if self.interface.is_unspecified() {
            resolve_local_ipv6().unwrap_or(Ipv6Addr::LOCALHOST)
        } else {
            self.interface
        };
        self.local_mac = encode_bip6_mac(local_ip, local_port);

        self.source_vmac = if let Some(id) = self.device_instance {
            derive_vmac_from_device_instance(id)
        } else {
            let local_v6 = SocketAddrV6::new(local_ip, local_port, 0, 0);
            derive_vmac_from_addr(&local_v6)
        };

        let if_index = if local_ip.is_loopback() {
            0u32
        } else {
            resolve_interface_index(&local_ip).unwrap_or_else(|| {
                warn!("Could not resolve interface index for {local_ip}, using OS default (0)");
                0u32
            })
        };
        for group in &[
            BACNET_IPV6_MULTICAST_LINK_LOCAL,
            BACNET_IPV6_MULTICAST_SITE_LOCAL,
            BACNET_IPV6_MULTICAST_ORG_LOCAL,
        ] {
            if let Err(e) = socket.join_multicast_v6(group, if_index) {
                warn!("Could not join IPv6 multicast group {group} on interface {if_index}: {e}");
            }
        }

        let socket = Arc::new(socket);
        self.socket = Some(Arc::clone(&socket));

        // VMAC collision detection and resolution
        {
            let multicast_dest =
                SocketAddrV6::new(BACNET_IPV6_MULTICAST_LINK_LOCAL, self.port, 0, if_index);
            let mut check_buf = vec![0u8; 64];

            for attempt in 0..=MAX_VMAC_RETRIES {
                let var_msg = encode_virtual_address_resolution(&self.source_vmac);
                let _ = socket.send_to(&var_msg, multicast_dest).await;

                let mut collision = false;
                let deadline = tokio::time::Instant::now() + Duration::from_millis(200);
                loop {
                    match tokio::time::timeout_at(
                        deadline,
                        destination_receiver.recv_from(&socket, &mut check_buf),
                    )
                    .await
                    {
                        Ok(Ok(received)) => {
                            if let Ok(frame) = decode_bvlc6(&check_buf[..received.len]) {
                                // VAR-ACK from another node using our VMAC
                                if frame.function == Bvlc6Function::VirtualAddressResolutionAck
                                    && frame.source_vmac == self.source_vmac
                                    && is_local_unicast_delivery(
                                        received.destination,
                                        frame.destination_vmac,
                                        local_ip,
                                        self.source_vmac,
                                        received.os_group_delivery,
                                    )
                                {
                                    collision = true;
                                    break;
                                }
                            }
                        }
                        Ok(Err(e)) => {
                            debug!(error = %e, "Error during VMAC collision check");
                            break;
                        }
                        Err(_) => break, // timeout elapsed — no collision
                    }
                }

                if !collision {
                    break;
                }

                if attempt < MAX_VMAC_RETRIES {
                    let old_vmac = self.source_vmac;
                    self.source_vmac = generate_random_vmac();
                    warn!(
                        old_vmac = ?old_vmac,
                        new_vmac = ?self.source_vmac,
                        attempt = attempt + 1,
                        max_retries = MAX_VMAC_RETRIES,
                        "BIP6 VMAC collision detected, re-deriving new VMAC"
                    );
                } else {
                    warn!(
                        vmac = ?self.source_vmac,
                        "BIP6 VMAC collision persists after {MAX_VMAC_RETRIES} retries, \
                         proceeding with current VMAC"
                    );
                }
            }
        }

        /// NPDU receive channel capacity for high-throughput UDP transports.
        const NPDU_CHANNEL_CAPACITY: usize = 256;

        let (tx, rx) = mpsc::channel(NPDU_CHANNEL_CAPACITY);
        let local_mac = self.local_mac;

        let source_vmac_copy = self.source_vmac;
        let socket_for_recv = Arc::clone(&socket);
        let vmac_table_clone = self.vmac_table.clone();
        let recv_task = tokio::spawn(async move {
            let mut recv_buf = vec![0u8; 2048];
            loop {
                match destination_receiver
                    .recv_from(&socket_for_recv, &mut recv_buf)
                    .await
                {
                    Ok(received) => {
                        let data = &recv_buf[..received.len];
                        match decode_bvlc6(data) {
                            Ok(frame) => {
                                if !destination_vmac_matches(
                                    frame.function,
                                    frame.destination_vmac,
                                    source_vmac_copy,
                                ) {
                                    debug!(
                                        function = frame.function.to_byte(),
                                        destination_vmac = ?frame.destination_vmac,
                                        "Dropping BVLC6 message addressed to another VMAC"
                                    );
                                    continue;
                                }
                                if !original_destination_matches(
                                    frame.function,
                                    received.destination,
                                    frame.destination_vmac,
                                    local_ip,
                                    source_vmac_copy,
                                    received.os_group_delivery,
                                ) {
                                    debug!(
                                        function = frame.function.to_byte(),
                                        destination = %received.destination,
                                        "Dropping BVLC6/IP or Destination-VMAC mismatch"
                                    );
                                    continue;
                                }
                                // Forwarded-NPDU's source VMAC identifies the original
                                // node, not the forwarding BBMD. Its original address is
                                // learned from the function payload below.
                                if frame.function != Bvlc6Function::ForwardedNpdu
                                    && frame.source_vmac != [0; 3]
                                {
                                    if let std::net::SocketAddr::V6(v6) = received.peer {
                                        vmac_table_clone.learn(frame.source_vmac, v6).await;
                                    }
                                }

                                match frame.function {
                                    Bvlc6Function::OriginalUnicast
                                    | Bvlc6Function::OriginalBroadcast => {
                                        let source_mac =
                                            if let std::net::SocketAddr::V6(v6) = received.peer {
                                                MacAddr::from_slice(&encode_bip6_mac(
                                                    *v6.ip(),
                                                    v6.port(),
                                                ))
                                            } else {
                                                continue;
                                            };
                                        if source_mac[..] == local_mac[..] {
                                            continue;
                                        }
                                        if tx
                                            .try_send(ReceivedNpdu {
                                                npdu: frame.payload.clone(),
                                                source_mac,
                                                link_layer_group: frame.function
                                                    == Bvlc6Function::OriginalBroadcast,
                                                data_attributes: Vec::new(),
                                                reply_tx: None,
                                            })
                                            .is_err()
                                        {
                                            warn!(
                                                "BIP6: NPDU channel full, dropping incoming frame"
                                            );
                                        }
                                    }

                                    Bvlc6Function::ForwardedNpdu => {
                                        match decode_forwarded_npdu_payload(&frame.payload) {
                                            Ok((mut source_addr, npdu_bytes)) => {
                                                if npdu_bytes.is_empty() {
                                                    debug!(
                                                    "ForwardedNpdu with no NPDU payload, ignoring"
                                                );
                                                    continue;
                                                }
                                                // A forwarded link-local address has no wire scope;
                                                // use the forwarding BBMD's ingress interface hint.
                                                if source_addr.ip().is_unicast_link_local()
                                                    && source_addr.scope_id() == 0
                                                {
                                                    if let std::net::SocketAddr::V6(peer) =
                                                        received.peer
                                                    {
                                                        source_addr.set_scope_id(peer.scope_id());
                                                    }
                                                }
                                                vmac_table_clone
                                                    .learn(frame.source_vmac, source_addr)
                                                    .await;
                                                let source_mac = encode_bip6_mac(
                                                    *source_addr.ip(),
                                                    source_addr.port(),
                                                );
                                                if tx
                                                    .try_send(ReceivedNpdu {
                                                        npdu: Bytes::copy_from_slice(npdu_bytes),
                                                        source_mac: MacAddr::from_slice(
                                                            &source_mac,
                                                        ),
                                                        link_layer_group: true,
                                                        data_attributes: Vec::new(),
                                                        reply_tx: None,
                                                    })
                                                    .is_err()
                                                {
                                                    warn!("BIP6: NPDU channel full, dropping forwarded frame");
                                                }
                                            }
                                            Err(e) => {
                                                debug!(
                                                    error = %e,
                                                    "Failed to decode ForwardedNpdu payload"
                                                );
                                            }
                                        }
                                    }

                                    Bvlc6Function::VirtualAddressResolution => {
                                        // VAR: sender is checking if anyone else uses their VMAC.
                                        // If the source VMAC matches ours, respond (collision).
                                        if frame.source_vmac == source_vmac_copy {
                                            debug!(
                                                vmac = ?source_vmac_copy,
                                                "Received VAR for our VMAC, sending VAR-Ack"
                                            );
                                            let ack = encode_virtual_address_resolution_ack(
                                                &source_vmac_copy,
                                                &frame.source_vmac,
                                            );
                                            let _ =
                                                socket_for_recv.send_to(&ack, received.peer).await;
                                        }
                                    }

                                    Bvlc6Function::AddressResolution => {
                                        // AR: sender wants to know our B/IPv6 address from our VMAC.
                                        // destination_vmac is the target being resolved.
                                        if let Some(target) = frame.destination_vmac {
                                            if target == source_vmac_copy {
                                                debug!(
                                                    vmac = ?source_vmac_copy,
                                                    "Received AR for our VMAC, sending AR-Ack"
                                                );
                                                let ack = encode_address_resolution_ack(
                                                    &source_vmac_copy,
                                                    &frame.source_vmac,
                                                );
                                                let _ = socket_for_recv
                                                    .send_to(&ack, received.peer)
                                                    .await;
                                            }
                                        }
                                    }

                                    Bvlc6Function::AddressResolutionAck => {
                                        // AR-ACK: learn the sender's VMAC→address mapping
                                        // (will be used by VMAC table in future)
                                        debug!(
                                            vmac = ?frame.source_vmac,
                                                addr = %received.peer,
                                            "Received AR-Ack"
                                        );
                                    }

                                    Bvlc6Function::VirtualAddressResolutionAck => {
                                        // VAR-ACK: someone responded to our collision check
                                        if frame.source_vmac == source_vmac_copy {
                                            warn!(
                                                vmac = ?source_vmac_copy,
                                                "BIP6 VMAC collision detected! \
                                                 Another node responded with our VMAC."
                                            );
                                        }
                                    }

                                    Bvlc6Function::Result => {
                                        // Log BVLC-Result for diagnostics
                                        if frame.payload.len() >= 2 {
                                            let result_code = u16::from_be_bytes([
                                                frame.payload[0],
                                                frame.payload[1],
                                            ]);
                                            if result_code == 0x0000 {
                                                debug!("BIP6: BVLC-Result successful");
                                            } else {
                                                tracing::error!(
                                                    code = result_code,
                                                    "BIP6: BVLC-Result NAK"
                                                );
                                            }
                                        }
                                    }

                                    _ => {
                                        debug!(
                                            function = ?frame.function,
                                            "Unhandled BVLC6 function"
                                        );
                                    }
                                }
                            }
                            Err(e) => {
                                warn!(error = %e, "Failed to decode BVLC6 frame");
                            }
                        }
                    }
                    Err(e) if e.kind() == std::io::ErrorKind::InvalidData => {
                        debug!(error = %e, "Dropping UDP datagram with invalid destination metadata");
                    }
                    Err(e) => {
                        warn!(error = %e, "IPv6 UDP recv error");
                        break;
                    }
                }
            }
        });

        self.recv_task = Some(recv_task);

        // Start foreign device registration if configured
        if let Some(fd) = &self.foreign_device {
            let bbmd_addr = SocketAddrV6::new(fd.bbmd_ip, fd.bbmd_port, 0, 0);
            let ttl = fd.ttl;
            let sock = Arc::clone(&socket);
            let source_vmac = self.source_vmac;

            // Send initial registration
            send_register_foreign_device_v6(&sock, bbmd_addr, ttl, &source_vmac).await;

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

        let dest = SocketAddrV6::new(self.broadcast_scope.multicast_addr(), self.port, 0, 0);
        let mut buf = BytesMut::with_capacity(BVLC6_HEADER_LENGTH + npdu.len());
        encode_bvlc6_original_broadcast(&mut buf, &source_vmac, npdu)?;

        socket.send_to(&buf, dest).await.map_err(Error::Transport)?;

        Ok(())
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
