//! BACnet/IPv6 ingress provenance checks.

use std::net::{IpAddr, Ipv6Addr, SocketAddr, SocketAddrV6};

use super::{
    Bip6Vmac, Bvlc6Function, BACNET_IPV6_MULTICAST_LINK_LOCAL, BACNET_IPV6_MULTICAST_ORG_LOCAL,
    BACNET_IPV6_MULTICAST_SITE_LOCAL,
};

fn is_bacnet_ipv6_multicast(destination: Ipv6Addr) -> bool {
    matches!(
        destination,
        BACNET_IPV6_MULTICAST_LINK_LOCAL
            | BACNET_IPV6_MULTICAST_SITE_LOCAL
            | BACNET_IPV6_MULTICAST_ORG_LOCAL
    )
}

pub(super) fn forwarded_source_is_usable(source: SocketAddrV6) -> bool {
    let ip = source.ip();
    source.port() != 0
        && !ip.is_unspecified()
        && !ip.is_multicast()
        && !ip.is_loopback()
        && ip.to_ipv4().is_none()
        // A Forwarded-NPDU carries no IPv6 scope ID. Synthesizing the BBMD's
        // ingress scope for a link-local origin can target the wrong link.
        && !ip.is_unicast_link_local()
}

/// Local addressing state that a received destination is judged against.
pub(super) struct LocalBinding<'a> {
    /// IP address the socket is bound to.
    pub(super) ip: Ipv6Addr,
    /// This node's virtual MAC.
    pub(super) vmac: Bip6Vmac,
    /// Unicast addresses of the local interfaces (used for wildcard binds).
    pub(super) unicast_ips: &'a [Ipv6Addr],
    /// Whether the socket is bound to the wildcard address.
    pub(super) wildcard_bind: bool,
}

pub(super) fn is_local_unicast_delivery(
    destination: IpAddr,
    destination_vmac: Option<Bip6Vmac>,
    local: &LocalBinding<'_>,
    os_group_delivery: Option<bool>,
) -> bool {
    let LocalBinding {
        ip: local_ip,
        vmac: local_vmac,
        unicast_ips: local_unicast_ips,
        wildcard_bind,
    } = *local;
    let ip_matches = match destination {
        IpAddr::V6(ip) if wildcard_bind => {
            !ip.is_multicast()
                && (local_unicast_ips.contains(&ip)
                    || (cfg!(windows) && os_group_delivery == Some(false)))
        }
        IpAddr::V6(ip) => ip == local_ip,
        IpAddr::V4(_) => false,
    };
    ip_matches && destination_vmac == Some(local_vmac) && os_group_delivery != Some(true)
}

/// Whether a datagram was sent to a group: an IPv6 multicast address, or a
/// delivery the OS reports as multicast or broadcast.
pub(super) fn group_destination(destination: IpAddr, os_group_delivery: Option<bool>) -> bool {
    matches!(destination, IpAddr::V6(ip) if ip.is_multicast()) || os_group_delivery == Some(true)
}

/// Whether a frame's BVLC function fits the address it was sent to.
///
/// Annex U keeps directed and broadcast NPDUs apart by addressing: a directed
/// NPDU goes to the recipient's unicast B/IPv6 address and VMAC in an
/// Original-Unicast-NPDU (U.2.2, U.3), and a broadcast goes to a B/IPv6
/// multicast group in an Original-Broadcast-NPDU (U.4). A frame that mixes the
/// two is dropped before its NPDU reaches the network layer.
pub(super) fn original_destination_matches(
    function: Bvlc6Function,
    destination: IpAddr,
    destination_vmac: Option<Bip6Vmac>,
    local: &LocalBinding<'_>,
    os_group_delivery: Option<bool>,
) -> bool {
    let LocalBinding {
        ip: local_ip,
        unicast_ips: local_unicast_ips,
        wildcard_bind,
        ..
    } = *local;
    match function {
        Bvlc6Function::OriginalUnicast
        | Bvlc6Function::AddressResolutionAck
        | Bvlc6Function::VirtualAddressResolutionAck => {
            is_local_unicast_delivery(destination, destination_vmac, local, os_group_delivery)
        }
        Bvlc6Function::VirtualAddressResolution => {
            let ip_matches = match destination {
                IpAddr::V6(ip) if wildcard_bind => {
                    !ip.is_multicast()
                        && (local_unicast_ips.contains(&ip)
                            || (cfg!(windows) && os_group_delivery == Some(false)))
                }
                IpAddr::V6(ip) => ip == local_ip,
                IpAddr::V4(_) => false,
            };
            ip_matches && os_group_delivery != Some(true)
        }
        Bvlc6Function::OriginalBroadcast | Bvlc6Function::AddressResolution => {
            matches!(destination, IpAddr::V6(ip) if is_bacnet_ipv6_multicast(ip))
                && os_group_delivery != Some(false)
        }
        // Forwarded-Address-Resolution is not implemented. Drop it before
        // learning or any other state mutation.
        Bvlc6Function::ForwardedAddressResolution => false,
        _ => true,
    }
}

pub(super) fn forwarded_npdu_is_trusted(
    peer: SocketAddr,
    destination: IpAddr,
    os_group_delivery: Option<bool>,
    local_ip: Ipv6Addr,
    local_unicast_ips: &[Ipv6Addr],
    wildcard_bind: bool,
    foreign_bbmd: Option<(Ipv6Addr, u16)>,
) -> bool {
    if let Some((bbmd_ip, bbmd_port)) = foreign_bbmd {
        let peer_matches = !bbmd_ip.is_unicast_link_local()
            && matches!(peer, SocketAddr::V6(peer) if *peer.ip() == bbmd_ip && peer.port() == bbmd_port);
        let destination_matches = match destination {
            IpAddr::V6(ip) if wildcard_bind => {
                !ip.is_multicast()
                    && (local_unicast_ips.contains(&ip)
                        || (cfg!(windows) && os_group_delivery == Some(false)))
            }
            IpAddr::V6(ip) => ip == local_ip,
            IpAddr::V4(_) => false,
        };
        peer_matches && destination_matches && os_group_delivery != Some(true)
    } else {
        matches!(destination, IpAddr::V6(ip) if is_bacnet_ipv6_multicast(ip))
            && os_group_delivery != Some(false)
    }
}
