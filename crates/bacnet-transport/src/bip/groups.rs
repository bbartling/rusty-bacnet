//! Which B/IP destinations reach a group of nodes (#1479), and the
//! Forwarded-NPDU origins the receive loop refuses for being one (#1493).

use std::net::Ipv4Addr;
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
        let own_broadcast = ip == self.broadcast;
        (own_broadcast && u16::from_be_bytes([high, low]) == self.port)
            || ip.is_broadcast()
            || ip.is_multicast()
            || (own_broadcast && !ip.is_loopback() && ip != self.interface)
    }
}

/// The receive loop's check on a Forwarded-NPDU's originating address
/// (#1493). The stack takes that address as the NPDU's source, so one that
/// is a group destination of this link ([`BipGroups`]) would let a forged
/// I-Am bind a device to a group, and send the answer to a request to every
/// node in it. No node sends from such an address, so the frame is
/// malformed: it is dropped before the network layer sees it, a BBMD
/// forwards it nowhere, and each one is counted.
#[derive(Clone)]
pub(super) struct ForwardedOrigins {
    groups: BipGroups,
    drops: Arc<AtomicU64>,
}

impl ForwardedOrigins {
    /// Refuse `groups`, counting each refusal in `drops`.
    pub(super) fn new(groups: BipGroups, drops: Arc<AtomicU64>) -> Self {
        Self { groups, drops }
    }

    /// A rule for receive contexts built in tests that don't exercise it:
    /// the limited broadcast and multicast addresses, with its own counter.
    #[cfg(test)]
    pub(super) fn detached() -> Self {
        let unspecified = Ipv4Addr::UNSPECIFIED;
        Self::new(BipGroups::new(unspecified, 0, unspecified), Arc::default())
    }

    /// Whether a Forwarded-NPDU from `origin` (its B/IP MAC) may go on. A
    /// group origin is counted and logged, and the frame goes no further.
    pub(super) fn admits(&self, origin: &[u8]) -> bool {
        if !self.groups.contains(origin) {
            return true;
        }
        self.drops.fetch_add(1, Ordering::Relaxed);
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
