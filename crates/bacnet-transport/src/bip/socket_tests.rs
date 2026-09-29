//! Socket options the B/IP transport sets at start.

use super::*;

#[tokio::test]
async fn socket_is_broadcast_capable_and_binds_inaddr_any() {
    // Regression for the "user-supplied interface IP" silently rejecting
    // broadcast traffic.  Even when the caller passes a specific interface,
    // the underlying socket must bind 0.0.0.0 so the kernel delivers
    // subnet- and limited-broadcast packets to it.  The interface IP is
    // still used for the announced local MAC.
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

#[tokio::test]
async fn only_an_explicit_port_opts_into_address_reuse() {
    // Linux can hand two SO_REUSEADDR sockets the same ephemeral port, and
    // unicast to it then reaches only one of them (#892).
    let mut ephemeral = BipTransport::new(Ipv4Addr::LOCALHOST, 0, Ipv4Addr::BROADCAST);
    let _rx = ephemeral.start().await.unwrap();
    assert!(!reuses_address(&ephemeral));
    let (_, port) = decode_bip_mac(ephemeral.local_mac()).unwrap();
    ephemeral.stop().await.unwrap();

    let mut explicit = BipTransport::new(Ipv4Addr::LOCALHOST, port, Ipv4Addr::BROADCAST);
    let _rx = explicit.start().await.unwrap();
    assert!(reuses_address(&explicit));
    explicit.stop().await.unwrap();
}
