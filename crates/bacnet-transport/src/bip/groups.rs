//! Which B/IP destinations reach a group of nodes (#1479).

use std::net::Ipv4Addr;

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

impl BipTransport {
    pub(super) fn groups(&self) -> BipGroups {
        BipGroups {
            broadcast: self.broadcast_address,
            port: self.port,
            interface: self.interface,
        }
    }
}
