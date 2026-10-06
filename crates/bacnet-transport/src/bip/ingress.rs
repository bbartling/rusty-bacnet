//! The B/IP receive loop, and what it does with one datagram before the BVLL
//! handler sees it: check that the BVLC function fits the address the
//! datagram was sent to, and say how it arrived.

use std::io;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::Arc;

use bacnet_types::enums::BvlcFunction;
use tracing::{debug, warn};

use crate::bvll::decode_bvll;
use crate::udp_metadata::{DestinationReceiver, IpVersion, ReceivedDatagram};

use super::io::{handle_bvll_message, RecvContext};
use super::socket::{BipSocket, BoundSockets};

/// Which of a transport's sockets a datagram arrived on (socket.rs).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Arrival {
    /// The socket every send leaves from.
    Primary,
    /// The receive-only wildcard socket beside a socket bound to the
    /// interface address, which keeps only broadcasts (#1538).
    BroadcastListener,
}

/// One socket the receive loop reads, with its own buffer.
pub(super) struct Listener {
    socket: Arc<BipSocket>,
    receiver: DestinationReceiver,
    buf: Vec<u8>,
}

impl Listener {
    /// Hand a bound socket to tokio, reading the destination of each
    /// datagram. Must run inside a tokio runtime.
    fn open(socket: socket2::Socket, lease: Option<Arc<()>>) -> io::Result<Self> {
        let receiver = DestinationReceiver::configure(&socket, IpVersion::V4)?;
        let socket = tokio::net::UdpSocket::from_std(socket.into())?;
        Ok(Self {
            socket: Arc::new(BipSocket::new(socket, lease)),
            receiver,
            buf: vec![0; 2048],
        })
    }

    async fn recv(&mut self) -> io::Result<ReceivedDatagram> {
        self.receiver.recv_from(&self.socket, &mut self.buf).await
    }
}

/// The sockets one receive loop reads.
pub(super) struct Listeners {
    primary: Listener,
    broadcast: Option<Listener>,
}

impl Listeners {
    /// Hand the sockets one start bound to tokio. Each keeps `lease` until
    /// it closes.
    pub(super) fn open(bound: BoundSockets, lease: Option<Arc<()>>) -> io::Result<Self> {
        Ok(Self {
            broadcast: bound
                .broadcast
                .map(|socket| Listener::open(socket, lease.clone()))
                .transpose()?,
            primary: Listener::open(bound.primary, lease)?,
        })
    }

    /// The socket every send leaves from.
    pub(super) fn primary(&self) -> &Arc<BipSocket> {
        &self.primary.socket
    }

    /// The next datagram on either socket. Each read is cancel-safe: the
    /// datagram leaves the socket only inside the read that returns it.
    async fn recv(&mut self) -> (Arrival, io::Result<ReceivedDatagram>) {
        let Self { primary, broadcast } = self;
        match broadcast {
            None => (Arrival::Primary, primary.recv().await),
            Some(listener) => tokio::select! {
                received = primary.recv() => (Arrival::Primary, received),
                received = listener.recv() => (Arrival::BroadcastListener, received),
            },
        }
    }

    fn data(&self, arrival: Arrival, len: usize) -> &[u8] {
        let listener = match (arrival, &self.broadcast) {
            (Arrival::BroadcastListener, Some(listener)) => listener,
            _ => &self.primary,
        };
        &listener.buf[..len]
    }
}

/// Read every datagram the transport's sockets receive, until one fails.
pub(super) async fn receive_loop(
    mut listeners: Listeners,
    local: IngressAddresses,
    ctx: RecvContext,
) {
    loop {
        let (arrival, received) = listeners.recv().await;
        match received {
            Ok(received) => {
                let data = listeners.data(arrival, received.len);
                handle_datagram(data, &received, arrival, &local, &ctx).await;
            }
            Err(e) if e.kind() == io::ErrorKind::InvalidData => {
                debug!(error = %e, "Dropping UDP datagram with invalid destination metadata");
            }
            Err(e) => {
                warn!(error = %e, "UDP recv error");
                break;
            }
        }
    }
}

/// How a datagram reached the B/IP socket, from its destination address.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Delivery {
    /// Sent to the configured broadcast address or 255.255.255.255, so every
    /// B/IP device on the subnet received it too.
    Broadcast,
    /// Any other destination.
    Unicast,
}

impl Delivery {
    /// Classify a datagram by its destination. An OS that flags the datagram
    /// as unicast delivery overrides a broadcast destination.
    pub(super) fn of(
        destination: IpAddr,
        configured_broadcast: Ipv4Addr,
        os_group_delivery: Option<bool>,
    ) -> Self {
        let broadcast = matches!(destination, IpAddr::V4(ip) if ip == configured_broadcast || ip == Ipv4Addr::BROADCAST)
            && os_group_delivery != Some(false);
        if broadcast {
            Self::Broadcast
        } else {
            Self::Unicast
        }
    }
}

/// How an inbound datagram arrived, or `None` when its BVLC function does not
/// fit the address it was sent to.
///
/// Annex J tells the two Original functions apart by where they are sent. An
/// Original-Unicast-NPDU carries a directed NPDU to one node's own address
/// (J.2.11, J.3); an Original-Broadcast-NPDU carries a local broadcast, sent to
/// the subnet's broadcast address (J.4.1). A datagram that mixes the two is
/// dropped here, before its NPDU reaches the network layer.
/// An Original-Unicast-NPDU sent to a broadcast address reached every B/IP
/// node on the subnet, so a confirmed request in it would draw an answer from
/// each of them.
///
/// Where an interface bind's configured broadcast address is also its own
/// address, as in a loopback test, the BVLC function picks the reading. A
/// wildcard bind never counts the configured broadcast address as its own, so
/// there an Original-Unicast-NPDU sent to it is dropped. The handler reports
/// the delivery returned here as an Original-Unicast-NPDU's
/// `link_layer_group`, so the flag and this check cannot disagree.
pub(super) fn admitted_delivery(
    function: BvlcFunction,
    destination: IpAddr,
    local_ip: Ipv4Addr,
    configured_broadcast: Ipv4Addr,
    local_unicast_ips: &[Ipv4Addr],
    wildcard_bind: bool,
    os_group_delivery: Option<bool>,
) -> Option<Delivery> {
    // A wildcard bind accepts unicast only to one of the host's listed
    // addresses, on every OS (#952).
    let local_unicast = match destination {
        IpAddr::V4(ip) if wildcard_bind => {
            ip != configured_broadcast
                && ip != Ipv4Addr::BROADCAST
                && !ip.is_multicast()
                && local_unicast_ips.contains(&ip)
        }
        IpAddr::V4(ip) => ip == local_ip,
        IpAddr::V6(_) => false,
    } && os_group_delivery != Some(true);
    let unicast = local_unicast.then_some(Delivery::Unicast);
    let broadcast = (Delivery::of(destination, configured_broadcast, os_group_delivery)
        == Delivery::Broadcast)
        .then_some(Delivery::Broadcast);

    match function {
        f if f == BvlcFunction::ORIGINAL_UNICAST_NPDU => unicast,
        f if f == BvlcFunction::ORIGINAL_BROADCAST_NPDU => broadcast,
        // A Forwarded-NPDU may arrive by direct unicast or by a configured
        // directed/limited broadcast, and counts as a broadcast when the
        // address fits both. All BVLL management requests and responses are
        // point-to-point and must arrive as actual unicast.
        f if f == BvlcFunction::FORWARDED_NPDU => broadcast.or(unicast),
        _ => unicast,
    }
}

/// Whether the configured broadcast address is one of this host's own
/// non-loopback addresses, as on a /32 or point-to-point link set up by
/// mistake. Broadcasts sent there reach only this host. Loopback tests use the
/// same setup on purpose, so loopback addresses don't count.
pub(super) fn broadcast_is_own_address(
    broadcast: Ipv4Addr,
    local_ip: Ipv4Addr,
    unicast_ips: &[Ipv4Addr],
) -> bool {
    !broadcast.is_loopback() && (broadcast == local_ip || unicast_ips.contains(&broadcast))
}

/// This node's own addresses, which an inbound datagram's destination is
/// judged against.
pub(super) struct IngressAddresses {
    /// The IP address in this node's B/IP MAC.
    pub(super) local_ip: Ipv4Addr,
    /// The host's IPv4 addresses, which a wildcard bind takes unicast to.
    pub(super) unicast_ips: Vec<Ipv4Addr>,
    /// Whether the socket is bound to 0.0.0.0 rather than an interface.
    pub(super) wildcard_bind: bool,
}

/// Decode one received datagram and hand it to the BVLL handler, unless its
/// BVLC function does not fit its destination, or it is not a broadcast and
/// came to the broadcast listener.
pub(super) async fn handle_datagram(
    data: &[u8],
    received: &ReceivedDatagram,
    arrival: Arrival,
    local: &IngressAddresses,
    ctx: &RecvContext,
) {
    let msg = match decode_bvll(data) {
        Ok(msg) => msg,
        Err(e) => {
            warn!(error = %e, "Failed to decode BVLL frame");
            return;
        }
    };
    let Some(delivery) = admitted_delivery(
        msg.function,
        received.destination,
        local.local_ip,
        ctx.broadcast_addr,
        &local.unicast_ips,
        local.wildcard_bind,
        received.os_group_delivery,
    ) else {
        debug!(
            function = msg.function.to_raw(),
            destination = %received.destination,
            "Dropping BVLL/IP destination mismatch"
        );
        return;
    };
    // Unicast to an address no other socket on the port is bound to also
    // reaches a wildcard socket. It is not this node's (a socket bound to its
    // own address takes that), and another node on this port may share the
    // listener, so the listener keeps broadcasts only.
    if arrival == Arrival::BroadcastListener && delivery != Delivery::Broadcast {
        debug!(
            destination = %received.destination,
            "Dropping unicast on the B/IP broadcast listener"
        );
        return;
    }
    let SocketAddr::V4(peer) = received.peer else {
        return;
    };
    handle_bvll_message(&msg, (peer.ip().octets(), peer.port()), delivery, ctx).await;
}
