//! The sockets a B/IP transport binds at start (#892, #950, #1538), and one
//! destruction order for a socket and the registered-object lease.
//!
//! A transport binds one of two ways:
//!
//! - **Wildcard:** one socket on `0.0.0.0:port`. Used when no interface is
//!   given, and for an explicit interface on a port the OS picks. Such a port
//!   is never shared (#892), so the wildcard socket owns it on every address,
//!   and the receive loop takes unicast only to the interface address.
//! - **Per address:** an explicit interface on an explicitly requested port
//!   binds `interface:port`, so transports on different addresses can share
//!   one port, each getting only its own unicast (#1538). Every send leaves
//!   from that socket, so its source is the interface address. How broadcasts
//!   arrive differs by OS:
//!   - Linux, macOS and the BSDs deliver a broadcast only to sockets bound to
//!     the wildcard address or to the broadcast address itself, so a second,
//!     receive-only socket binds `0.0.0.0:port` and the receive loop keeps only
//!     the broadcasts it gets. Linux delivers a broadcast to every
//!     `SO_REUSEADDR` socket on the port and a unicast to the most specific
//!     bind. macOS and the BSDs also need `SO_REUSEPORT` before several
//!     sockets can bind `0.0.0.0:port`, and deliver a broadcast to each.
//!     The receive loop reads the two sockets fairly, in no fixed order, so
//!     a broadcast and a unicast that arrive together may be handled in
//!     either order. UDP never promised one.
//!   - Windows delivers a broadcast arriving on the interface to a socket bound
//!     to the interface address, so that one socket is enough. Its
//!     `SO_REUSEADDR` would let another socket bind the same address and take
//!     the unicast sent there, so it claims the address with
//!     `SO_EXCLUSIVEADDRUSE` instead, as `port_ownership` does for a private
//!     port (#950). Sockets on other addresses can still share the port.

use std::io;
use std::net::{Ipv4Addr, SocketAddrV4};
use std::{ops::Deref, sync::Arc};

use bacnet_types::error::Error;
use tokio::net::UdpSocket;

/// What a socket is for, which decides how it shares its port.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum SocketRole {
    /// `0.0.0.0` on a port the OS picks. Linux gives an ephemeral port to an
    /// `SO_REUSEADDR` socket even while another `SO_REUSEADDR` socket owns it,
    /// and unicast to that port then reaches only one of them (#892), so it
    /// never sets the option, and claims the port where the OS has a way to
    /// (`port_ownership`, #950).
    PrivateWildcard,
    /// `0.0.0.0` on an explicitly requested port: `SO_REUSEADDR`, as before.
    SharedWildcard,
    /// `interface:port` on an explicitly requested port (#1538): a socket
    /// beside the [`BroadcastListener`](Self::BroadcastListener) on Unix, a
    /// claimed address on Windows.
    Address,
    /// `0.0.0.0` beside an [`Address`](Self::Address) socket, for broadcasts
    /// only. Not used on Windows.
    BroadcastListener,
}

/// An unbound UDP socket set up for `role`.
pub(super) fn udp_socket(role: SocketRole) -> io::Result<socket2::Socket> {
    let socket = socket2::Socket::new(
        socket2::Domain::IPV4,
        socket2::Type::DGRAM,
        Some(socket2::Protocol::UDP),
    )?;
    match role {
        SocketRole::PrivateWildcard => crate::port_ownership::claim_exclusive(&socket)?,
        SocketRole::SharedWildcard => socket.set_reuse_address(true)?,
        #[cfg(windows)]
        SocketRole::Address => crate::port_ownership::claim_exclusive(&socket)?,
        #[cfg(not(windows))]
        SocketRole::Address => socket.set_reuse_address(true)?,
        SocketRole::BroadcastListener => {
            socket.set_reuse_address(true)?;
            #[cfg(any(
                target_vendor = "apple",
                target_os = "freebsd",
                target_os = "dragonfly",
                target_os = "openbsd",
                target_os = "netbsd",
            ))]
            socket.set_reuse_port(true)?;
        }
    }
    socket.set_broadcast(true)?;
    socket.set_nonblocking(true)?;
    Ok(socket)
}

/// The sockets one start binds: the one every send leaves from, and on Unix,
/// when it is bound to an interface address, the one broadcasts arrive on.
pub(super) struct BoundSockets {
    pub(super) primary: socket2::Socket,
    pub(super) broadcast: Option<socket2::Socket>,
}

impl super::BipTransport {
    /// Check that a transport for `interface` and `port` could start now:
    /// bind the sockets [`start`](crate::port::TransportPort::start) would,
    /// with the same options, and release them. Another socket can still
    /// take the port before the real start, which stays authoritative.
    pub fn check_bind(interface: Ipv4Addr, port: u16) -> Result<(), Error> {
        probe_interface(interface)?;
        bind(interface, port, port != 0)
            .map(drop)
            .map_err(Error::Transport)
    }
}

/// Fail on an interface address this host doesn't have. A wildcard bind
/// would succeed anyway, so this binds a throwaway socket on an ephemeral
/// port: a misconfigured interface fails fast at startup rather than
/// silently advertising an unowned IP in I-Am replies via the local MAC
/// (tests::start_fails_on_nonlocal_interface).
pub(super) fn probe_interface(interface: Ipv4Addr) -> Result<(), Error> {
    if !interface.is_unspecified() {
        std::net::UdpSocket::bind(SocketAddrV4::new(interface, 0)).map_err(Error::Transport)?;
    }
    Ok(())
}

/// Bind the sockets for `interface` and `port` as the module docs describe.
/// `share_port` says whether the port was explicitly requested.
pub(super) fn bind(interface: Ipv4Addr, port: u16, share_port: bool) -> io::Result<BoundSockets> {
    let bound = |role: SocketRole, ip: Ipv4Addr| -> io::Result<socket2::Socket> {
        let socket = udp_socket(role)?;
        socket.bind(&SocketAddrV4::new(ip, port).into())?;
        Ok(socket)
    };
    if interface.is_unspecified() || !share_port {
        let role = if share_port {
            SocketRole::SharedWildcard
        } else {
            SocketRole::PrivateWildcard
        };
        return Ok(BoundSockets {
            primary: bound(role, Ipv4Addr::UNSPECIFIED)?,
            broadcast: None,
        });
    }
    let primary = bound(SocketRole::Address, interface)?;
    let broadcast = if cfg!(windows) {
        None
    } else {
        Some(bound(SocketRole::BroadcastListener, Ipv4Addr::UNSPECIFIED)?)
    };
    Ok(BoundSockets { primary, broadcast })
}

/// Every socket-owning worker retains this same allocation. Rust drops fields
/// in declaration order: the socket closes before the final registration token.
pub(super) struct BipSocket {
    socket: UdpSocket,
    _network_port_lease: Option<Arc<()>>,
}

impl BipSocket {
    pub(super) fn new(socket: UdpSocket, lease: Option<Arc<()>>) -> Self {
        Self {
            socket,
            _network_port_lease: lease,
        }
    }
}

impl Deref for BipSocket {
    type Target = UdpSocket;
    fn deref(&self) -> &Self::Target {
        &self.socket
    }
}
