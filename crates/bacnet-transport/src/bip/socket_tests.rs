//! Socket options the B/IP transport sets at start.

use super::*;
use crate::port_ownership::{restart, ATTEMPTS};
use socket::{udp_socket, BoundSockets, SocketRole};

#[tokio::test]
async fn socket_is_broadcast_capable_and_binds_inaddr_any() {
    // Regression for the "user-supplied interface IP" silently rejecting
    // broadcast traffic. On an ephemeral port, even when the caller passes a
    // specific interface, the one socket binds 0.0.0.0 so the kernel delivers
    // subnet- and limited-broadcast packets to it. The interface IP is still
    // used for the announced local MAC.
    let mut transport = BipTransport::new(Ipv4Addr::LOCALHOST, 0, Ipv4Addr::BROADCAST);
    let _rx = transport.start().await.unwrap();

    let local = transport
        .socket
        .as_ref()
        .expect("socket exists after start")
        .local_addr()
        .expect("local_addr is queryable");

    assert!(
        local.ip().is_unspecified(),
        "BIP socket must bind to 0.0.0.0 for broadcast reception; got {local}"
    );
    assert!(
        socket2::SockRef::from(
            &**transport
                .socket
                .as_ref()
                .expect("socket exists after start")
                .as_ref()
        )
        .broadcast()
        .expect("SO_BROADCAST is queryable"),
        "BIP socket must enable SO_BROADCAST for Original-Broadcast-NPDU sends"
    );

    // The announced local MAC must still reflect the user-supplied interface,
    // not the bind address.
    let mac = transport.local_mac();
    assert_eq!(
        &mac[..4],
        &Ipv4Addr::LOCALHOST.octets(),
        "announced IP must match interface"
    );

    transport.stop().await.unwrap();
}

fn reuses_address(transport: &BipTransport) -> bool {
    let socket = transport
        .socket
        .as_ref()
        .expect("socket exists after start");
    socket2::SockRef::from(&***socket)
        .reuse_address()
        .expect("SO_REUSEADDR is queryable")
}

#[test]
fn only_an_explicitly_requested_port_opts_into_address_reuse() {
    // Linux can hand two SO_REUSEADDR sockets the same ephemeral port, and
    // unicast to it then reaches only one of them (#892).
    let reuses = |role| udp_socket(role).unwrap().reuse_address().unwrap();
    assert!(!reuses(SocketRole::PrivateWildcard));
    assert!(reuses(SocketRole::SharedWildcard));
    // Windows claims an interface address instead of sharing it (#1538).
    assert_eq!(reuses(SocketRole::Address), cfg!(not(windows)));
    assert!(!BipTransport::new(Ipv4Addr::LOCALHOST, 0, Ipv4Addr::BROADCAST).share_port);
    assert!(BipTransport::new(Ipv4Addr::LOCALHOST, 0xBAC0, Ipv4Addr::BROADCAST).share_port);
}

/// Where `bind` put a socket.
fn address_of(socket: &socket2::Socket) -> SocketAddrV4 {
    socket.local_addr().unwrap().as_socket_ipv4().unwrap()
}

/// `socket::bind` for an explicitly requested port, which the OS picks here
/// and the probe releases first. Another process can take it in between
/// (#1032), so each run of `check` gets a fresh one.
fn on_a_requested_port(interface: Ipv4Addr, check: impl Fn(u16, BoundSockets)) {
    for attempt in 1..=ATTEMPTS {
        let port = std::net::UdpSocket::bind((Ipv4Addr::UNSPECIFIED, 0))
            .unwrap()
            .local_addr()
            .unwrap()
            .port();
        match socket::bind(interface, port, true) {
            Ok(bound) => return check(port, bound),
            Err(e) if crate::port_ownership::lost_port(attempt, &e) => continue,
            Err(e) => panic!("bind {interface}:{port}: {e}"),
        }
    }
}

#[test]
fn an_explicit_interface_on_a_requested_port_binds_its_address() {
    on_a_requested_port(Ipv4Addr::LOCALHOST, |port, bound| {
        assert_eq!(
            address_of(&bound.primary),
            SocketAddrV4::new(Ipv4Addr::LOCALHOST, port)
        );
        // Windows hands a socket bound to the interface address the
        // broadcasts that arrive there; Unix needs a wildcard listener.
        assert_eq!(bound.broadcast.is_none(), cfg!(windows));
        if let Some(listener) = bound.broadcast {
            assert_eq!(
                address_of(&listener),
                SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, port)
            );
            assert!(listener.reuse_address().unwrap());
            assert!(listener.broadcast().unwrap());
            // Several listeners on one port need it there.
            #[cfg(any(
                target_vendor = "apple",
                target_os = "freebsd",
                target_os = "dragonfly",
                target_os = "openbsd",
                target_os = "netbsd",
            ))]
            assert!(listener.reuse_port().unwrap());
        }
    });
}

#[test]
fn a_wildcard_or_a_private_port_keeps_one_wildcard_socket() {
    on_a_requested_port(Ipv4Addr::UNSPECIFIED, |port, bound| {
        assert_eq!(
            address_of(&bound.primary),
            SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, port)
        );
        assert!(bound.primary.reuse_address().unwrap());
        assert!(bound.broadcast.is_none());
    });
    // An ephemeral port is never shared (#892), so an explicit interface
    // gains nothing from its own bind there.
    let bound = socket::bind(Ipv4Addr::LOCALHOST, 0, false).unwrap();
    assert!(address_of(&bound.primary).ip().is_unspecified());
    assert!(!bound.primary.reuse_address().unwrap());
    assert!(bound.broadcast.is_none());
}

#[tokio::test]
async fn an_ephemeral_port_stays_private_across_restart() {
    // A restart rebinds the remembered actual port, which must not opt the
    // socket into sharing it. Each run starts on a fresh port; see `restart`
    // for why it can lose it.
    for attempt in 1..=ATTEMPTS {
        let mut transport = BipTransport::new(Ipv4Addr::LOCALHOST, 0, Ipv4Addr::BROADCAST);
        let _rx = transport.start().await.unwrap();
        assert!(!reuses_address(&transport));
        transport.stop().await.unwrap();
        let Some(started) = restart(&mut transport, attempt).await else {
            continue;
        };
        let _rx = started.unwrap();
        assert!(!reuses_address(&transport));
        transport.stop().await.unwrap();
        return;
    }
}

#[tokio::test]
async fn check_bind_refuses_what_start_would() {
    assert!(BipTransport::check_bind(Ipv4Addr::new(192, 0, 2, 1), 0).is_err());
    // A private port refuses a requested-port bind on every OS. macOS lets
    // the address socket beside it bind, but not the broadcast listener.
    let mut holder = BipTransport::new(Ipv4Addr::LOCALHOST, 0, Ipv4Addr::BROADCAST);
    let _rx = holder.start().await.unwrap();
    assert!(BipTransport::check_bind(Ipv4Addr::LOCALHOST, holder.port).is_err());
    assert!(BipTransport::check_bind(Ipv4Addr::UNSPECIFIED, holder.port).is_err());
    holder.stop().await.unwrap();
}
