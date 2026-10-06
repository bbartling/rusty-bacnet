//! Which B/IP destinations reach a group of nodes (#1479), and the senders
//! the receive loop refuses for being one: a datagram's UDP source (#1504)
//! and a Forwarded-NPDU's originating address (#1493).

use std::net::{Ipv4Addr, SocketAddrV4};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

use tracing::debug;

use super::BipTransport;

/// A B/IP link's group destinations, as [`TransportPort::is_group_destination`](crate::port::TransportPort::is_group_destination)
/// reads them (#1479): this link's broadcast MAC, the limited broadcast
/// 255.255.255.255 or the configured broadcast IP at any UDP port, and any
/// IPv4 multicast address (224.0.0.0/4). The socket may send to each, since
/// it sets SO_BROADCAST, and each reaches more than one node. A configured
/// broadcast IP that is a loopback address or this link's own interface,
/// as loopback tests set it up, counts only at this link's port, as
/// [`TransportPort::is_broadcast_mac`](crate::port::TransportPort::is_broadcast_mac) has it.
#[derive(Debug, Clone, Copy)]
pub(super) struct BipGroups {
    broadcast: Ipv4Addr,
    port: u16,
    interface: Ipv4Addr,
}

impl BipGroups {
    /// The groups of a link bound to `interface` at `port` whose configured
    /// broadcast IP is `broadcast`.
    pub(super) fn new(broadcast: Ipv4Addr, port: u16, interface: Ipv4Addr) -> Self {
        Self {
            broadcast,
            port,
            interface,
        }
    }

    pub(super) fn contains(self, mac: &[u8]) -> bool {
        let Ok(&[a, b, c, d, high, low]) = <&[u8; 6]>::try_from(mac) else {
            return false;
        };
        let ip = Ipv4Addr::new(a, b, c, d);
        (ip == self.broadcast && u16::from_be_bytes([high, low]) == self.port)
            || self.is_group_ip(ip)
    }

    /// A group address whatever the port: the limited broadcast, a
    /// multicast address, or the configured broadcast IP unless it is one of
    /// this node's own addresses. Only that last case leaves
    /// [`Self::contains`] to the port, so this is the test for a sender: a
    /// datagram from this link's own address and port is this node's own.
    fn is_group_ip(self, ip: Ipv4Addr) -> bool {
        ip.is_broadcast()
            || ip.is_multicast()
            || (ip == self.broadcast && !ip.is_loopback() && ip != self.interface)
    }
}

/// The receive loop's checks on the addresses a datagram names as its
/// sender: its UDP source (#1504) and, in a Forwarded-NPDU, the originating
/// address (#1493). The stack takes the sender as the NPDU's source and
/// answers it there, and a BBMD registers it as a foreign device or forwards
/// from it. One that is a group address of this link ([`BipGroups`]) would
/// let a forged I-Am bind a device to a group, and send the answer to a
/// request, or a confirmed COV notification, to every node in it. No node
/// sends from such an address, so the datagram is dropped before any BVLC
/// function is handled, a BBMD forwards it nowhere, and each one is counted.
#[derive(Clone)]
pub(super) struct GroupSources {
    groups: BipGroups,
    sender_drops: Arc<AtomicU64>,
    origin_drops: Arc<AtomicU64>,
}

impl GroupSources {
    /// Refuse `groups`, counting a refused UDP source in `sender_drops` and
    /// a refused Forwarded-NPDU origin in `origin_drops`.
    pub(super) fn new(
        groups: BipGroups,
        sender_drops: Arc<AtomicU64>,
        origin_drops: Arc<AtomicU64>,
    ) -> Self {
        Self {
            groups,
            sender_drops,
            origin_drops,
        }
    }

    /// A rule for receive contexts built in tests that don't exercise it:
    /// the limited broadcast and multicast addresses, with its own counters.
    #[cfg(test)]
    pub(super) fn detached() -> Self {
        let unspecified = Ipv4Addr::UNSPECIFIED;
        let groups = BipGroups::new(unspecified, 0, unspecified);
        Self::new(groups, Arc::default(), Arc::default())
    }

    /// Whether a datagram from UDP source `sender` may go on. A group source
    /// is counted and logged, and the datagram goes no further.
    pub(super) fn admits_sender(&self, sender: SocketAddrV4) -> bool {
        if !self.groups.is_group_ip(*sender.ip()) {
            return true;
        }
        self.sender_drops.fetch_add(1, Ordering::Relaxed);
        debug!(%sender, "Dropping a datagram whose UDP source is a group address");
        false
    }

    /// Whether a Forwarded-NPDU from `origin` (its B/IP MAC) may go on. A
    /// group origin is counted and logged, and the frame goes no further.
    pub(super) fn admits_origin(&self, origin: &[u8]) -> bool {
        if !self.groups.contains(origin) {
            return true;
        }
        self.origin_drops.fetch_add(1, Ordering::Relaxed);
        debug!(
            ?origin,
            "Dropping Forwarded-NPDU whose origin is a group address"
        );
        false
    }
}

impl BipTransport {
    pub(super) fn groups(&self) -> BipGroups {
        BipGroups::new(self.broadcast_address, self.port, self.interface)
    }

    /// The rule the receive loop judges senders by, with this transport's
    /// counters.
    pub(super) fn group_sources(&self) -> GroupSources {
        GroupSources::new(
            self.groups(),
            Arc::clone(&self.group_source_drops),
            Arc::clone(&self.forwarded_group_origin_drops),
        )
    }

    /// Datagrams dropped since this transport was created because their UDP
    /// source address is a group address of this link: the limited
    /// broadcast, a multicast address, or the configured broadcast IP
    /// (#1504). No node sends from one, and an answer to it would reach
    /// every node in the group, so the datagram is dropped before any BVLC
    /// function is handled: it never reaches the network layer, and a BBMD
    /// neither registers nor forwards from it. Linux already discards most
    /// such datagrams; other systems may not. The total survives a restart.
    pub fn group_source_drops(&self) -> u64 {
        self.group_source_drops.load(Ordering::Relaxed)
    }

    /// Forwarded-NPDUs dropped since this transport was created because
    /// their originating address is one of this link's group destinations
    /// ([`TransportPort::is_group_destination`](crate::port::TransportPort::is_group_destination)),
    /// such as the limited broadcast or a multicast address (#1493). No node
    /// sends from one, so such a frame is malformed: it never reaches the
    /// network layer, and a BBMD forwards it nowhere. The total survives a
    /// restart.
    pub fn forwarded_group_origin_drops(&self) -> u64 {
        self.forwarded_group_origin_drops.load(Ordering::Relaxed)
    }
}
