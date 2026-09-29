//! One socket/port, selected normal-mode source and receive authority.

use std::{
    io,
    net::{IpAddr, Ipv6Addr, SocketAddr, SocketAddrV6},
};
use tokio::net::UdpSocket;

use super::{
    link::SelectedLink, send::SelectedSender, BACNET_IPV6_MULTICAST_LINK_LOCAL,
    BACNET_IPV6_MULTICAST_ORG_LOCAL, BACNET_IPV6_MULTICAST_SITE_LOCAL,
};
use crate::udp_metadata::{DestinationReceiver, IpVersion, ReceivedDatagram};

pub(super) struct Bip6Socket {
    udp: UdpSocket,
    receiver: DestinationReceiver,
    pub selection: Option<SelectedLink>,
    sender: Option<SelectedSender>,
}

impl Bip6Socket {
    pub async fn bind(
        requested: Ipv6Addr,
        port: u16,
        foreign: Option<SocketAddrV6>,
    ) -> io::Result<Self> {
        let selection = if foreign.is_none() {
            Some(SelectedLink::resolve(requested).await?)
        } else {
            None
        };
        let socket = socket2::Socket::new(
            socket2::Domain::IPV6,
            socket2::Type::DGRAM,
            Some(socket2::Protocol::UDP),
        )?;
        socket.set_only_v6(true)?;
        // Only an explicit port opts into sharing: Linux would otherwise hand
        // this ephemeral bind a port another SO_REUSEADDR socket owns (#892).
        if port != 0 {
            socket.set_reuse_address(true)?;
        }
        socket.set_nonblocking(true)?;
        socket.set_multicast_loop_v6(true)?;
        let bound = if let Some(bbmd) = foreign {
            foreign_bind_address(requested, port, bbmd)?
        } else {
            SocketAddrV6::new(Ipv6Addr::UNSPECIFIED, port, 0, 0)
        };
        socket.bind(&bound.into())?;
        let receiver = DestinationReceiver::configure(&socket, IpVersion::V6)?;
        let sender = if let Some(link) = selection {
            socket.set_multicast_if_v6(link.index)?;
            for group in [
                BACNET_IPV6_MULTICAST_LINK_LOCAL,
                BACNET_IPV6_MULTICAST_SITE_LOCAL,
                BACNET_IPV6_MULTICAST_ORG_LOCAL,
            ] {
                socket.join_multicast_v6(&group, link.index)?;
            }
            Some(SelectedSender::new(&socket)?)
        } else {
            None
        };
        Ok(Self {
            udp: UdpSocket::from_std(socket.into())?,
            receiver,
            selection,
            sender,
        })
    }

    pub fn local_address(&self) -> io::Result<SocketAddrV6> {
        match self.udp.local_addr()? {
            SocketAddr::V6(address) => Ok(address),
            _ => Err(io::Error::other("IPv6 socket returned a non-IPv6 address")),
        }
    }
    pub fn local_port(&self) -> io::Result<u16> {
        Ok(self.local_address()?.port())
    }

    pub async fn send_to(&self, bytes: &[u8], peer: impl Into<SocketAddr>) -> io::Result<usize> {
        let peer = peer.into();
        match (self.selection, &self.sender, peer) {
            (Some(link), Some(sender), SocketAddr::V6(peer)) => {
                sender.send(&self.udp, bytes, peer, link).await
            }
            (None, None, peer) => self.udp.send_to(bytes, peer).await,
            _ => Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "invalid selected IPv6 socket destination",
            )),
        }
    }

    pub async fn recv_from(&self, bytes: &mut [u8]) -> io::Result<ReceivedDatagram> {
        let mut received = self.receiver.recv_from(&self.udp, bytes).await?;
        if let Some(link) = self.selection {
            if !admits(link, &received) {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "datagram is outside selected IPv6 link/address",
                ));
            }
            if let SocketAddr::V6(peer) = &mut received.peer {
                if peer.ip().is_unicast_link_local() {
                    peer.set_scope_id(link.index);
                }
            }
        }
        Ok(received)
    }
}

fn foreign_bind_address(
    requested: Ipv6Addr,
    port: u16,
    bbmd: SocketAddrV6,
) -> io::Result<SocketAddrV6> {
    if !requested.is_unspecified() {
        return Ok(SocketAddrV6::new(requested, port, 0, 0));
    }
    // A UDP connect selects a route/source without sending a packet. Bind the
    // production socket to that exact source, so subsequent registration and
    // DBTN cannot silently advertise one address while using another.
    let probe = std::net::UdpSocket::bind(SocketAddrV6::new(Ipv6Addr::UNSPECIFIED, 0, 0, 0))?;
    probe.connect(bbmd)?;
    match probe.local_addr()? {
        SocketAddr::V6(mut address)
            if !address.ip().is_unspecified() && !address.ip().is_multicast() =>
        {
            address.set_port(port);
            Ok(address)
        }
        _ => Err(io::Error::new(
            io::ErrorKind::AddrNotAvailable,
            "no concrete IPv6 source for configured BBMD",
        )),
    }
}

fn admits(link: SelectedLink, datagram: &ReceivedDatagram) -> bool {
    datagram.arrival_index == Some(link.index)
        && link.index != 0
        && matches!(datagram.destination, IpAddr::V6(ip) if ip == link.address
            || [BACNET_IPV6_MULTICAST_LINK_LOCAL, BACNET_IPV6_MULTICAST_SITE_LOCAL,
                BACNET_IPV6_MULTICAST_ORG_LOCAL].contains(&ip))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn only_an_explicit_port_opts_into_address_reuse() {
        let ephemeral = Bip6Socket::bind(Ipv6Addr::LOCALHOST, 0, None)
            .await
            .unwrap();
        assert!(!socket2::SockRef::from(&ephemeral.udp)
            .reuse_address()
            .unwrap());
        let port = ephemeral.local_port().unwrap();
        drop(ephemeral);
        let explicit = Bip6Socket::bind(Ipv6Addr::LOCALHOST, port, None)
            .await
            .unwrap();
        assert!(socket2::SockRef::from(&explicit.udp)
            .reuse_address()
            .unwrap());
    }

    #[test]
    fn arrival_interface_and_selected_destination_are_required_before_learning() {
        let link = SelectedLink {
            address: "fd12::1".parse().unwrap(),
            index: 3,
        };
        let mut datagram = ReceivedDatagram {
            len: 11,
            peer: "[fd12::2]:47808".parse().unwrap(),
            destination: IpAddr::V6(BACNET_IPV6_MULTICAST_SITE_LOCAL),
            arrival_index: Some(3),
            os_group_delivery: None,
        };
        assert!(admits(link, &datagram));
        for index in [None, Some(0), Some(4)] {
            datagram.arrival_index = index;
            assert!(!admits(link, &datagram));
        }
        datagram.arrival_index = Some(3);
        datagram.destination = IpAddr::V6(link.address);
        assert!(admits(link, &datagram));
        for destination in ["fd12::9", "::1", "::", "ff05::1"] {
            datagram.destination = IpAddr::V6(destination.parse().unwrap());
            assert!(!admits(link, &datagram));
        }
    }
}
