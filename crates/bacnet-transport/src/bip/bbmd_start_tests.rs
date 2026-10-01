//! A BBMD's own B/IP address with a wildcard bind, at start and restart (#937).

use super::bbmd_start::{select_wildcard_bbmd_ip, BdtSource};
use super::own_broadcast_tests::{
    assert_no_bvll, assert_own_forwarded, port_of, recv_bvll, udp, NPDU,
};
use super::*;

const PORT: u16 = 47808;
/// Stand-ins for the host's LAN addresses; tests only inject them.
const LAN: Ipv4Addr = Ipv4Addr::new(192, 0, 2, 10);
const OTHER_LAN: Ipv4Addr = Ipv4Addr::new(198, 51, 100, 7);
const REMOTE_PEER: Ipv4Addr = Ipv4Addr::new(203, 0, 113, 5);

fn row(ip: Ipv4Addr, port: u16) -> BdtEntry {
    BdtEntry {
        ip: ip.octets(),
        port,
        broadcast_mask: [255; 4],
    }
}

fn select(
    rows: &[BdtEntry],
    local: &[Ipv4Addr],
    route: Option<Ipv4Addr>,
) -> Result<Ipv4Addr, Error> {
    select_wildcard_bbmd_ip(rows, PORT, local, route, BdtSource::Configured)
}

/// A UDP port that was free a moment ago, so a BDT row can name the port the
/// transport is about to bind.
fn free_port() -> u16 {
    std::net::UdpSocket::bind(SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, 0))
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

/// A BBMD bound to `0.0.0.0`. `local` replaces the host's IPv4 addresses and
/// default-route address; `None` reads the real ones.
fn wildcard_bbmd(
    port: u16,
    bdt: Vec<BdtEntry>,
    local: Option<(Vec<Ipv4Addr>, Option<Ipv4Addr>)>,
) -> BipTransport {
    let mut transport = BipTransport::new(Ipv4Addr::UNSPECIFIED, port, Ipv4Addr::LOCALHOST);
    transport.enable_bbmd(bdt);
    transport.local_ipv4_for_test = local;
    transport
}

#[test]
fn wildcard_selection_takes_the_one_local_row_at_the_bound_port() {
    let local = [Ipv4Addr::LOCALHOST, LAN, OTHER_LAN];
    // A remote peer, a local address at another port and a repeated row do
    // not make the choice ambiguous, and the own row wins over the route.
    let rows = [
        row(REMOTE_PEER, PORT),
        row(LAN, PORT + 1),
        row(OTHER_LAN, PORT),
        row(OTHER_LAN, PORT),
    ];
    assert_eq!(select(&rows, &local, Some(LAN)).unwrap(), OTHER_LAN);
    // A loopback row is a local address like any other.
    assert_eq!(
        select(&[row(Ipv4Addr::LOCALHOST, PORT)], &local, Some(LAN)).unwrap(),
        Ipv4Addr::LOCALHOST
    );
}

#[test]
fn wildcard_selection_refuses_several_own_rows() {
    let rows = [row(LAN, PORT), row(Ipv4Addr::LOCALHOST, PORT)];
    let err = select(&rows, &[Ipv4Addr::LOCALHOST, LAN], Some(LAN)).unwrap_err();
    assert!(matches!(err, Error::Transport(_)), "{err:?}");
    let text = err.to_string();
    assert!(
        text.contains("the configured BDT has rows for several local IPv4 addresses")
            && text.contains("(127.0.0.1:47808, 192.0.2.10:47808)")
            && text.contains("bind an explicit interface address"),
        "{text}"
    );
}

#[test]
fn wildcard_selection_without_own_row_needs_a_local_non_loopback_route() {
    let local = [Ipv4Addr::LOCALHOST, LAN];
    let peers = [row(REMOTE_PEER, PORT)];
    assert_eq!(select(&peers, &local, Some(LAN)).unwrap(), LAN);
    // No route, a loopback route, and a route address not on this host.
    for route in [None, Some(Ipv4Addr::LOCALHOST), Some(OTHER_LAN)] {
        let err = select(&peers, &local, route).unwrap_err();
        assert!(matches!(err, Error::Transport(_)), "{err:?}");
        let text = err.to_string();
        assert!(
            text.contains("has no row for a local IPv4 address at port 47808")
                && text.contains("bind an explicit interface address")
                && text.contains("add this BBMD's own row to the BDT"),
            "{route:?}: {text}"
        );
    }
}

#[test]
fn wildcard_selection_trusts_a_non_loopback_route_when_addresses_cannot_be_listed() {
    // Windows: no local address list, so no row can be confirmed as local.
    let rows = [row(LAN, PORT), row(REMOTE_PEER, PORT)];
    assert_eq!(select(&rows, &[], Some(LAN)).unwrap(), LAN);
    for route in [None, Some(Ipv4Addr::LOCALHOST)] {
        let text = select(&rows, &[], route).unwrap_err().to_string();
        assert!(
            text.contains("the host's addresses cannot be listed")
                && text.contains("bind an explicit interface address"),
            "{route:?}: {text}"
        );
    }
}

#[cfg(unix)]
#[tokio::test]
async fn wildcard_bbmd_uses_its_own_bdt_row_as_origin_and_local_mac() {
    let bdt_peer = udp().await;
    let port = free_port();
    let own = (Ipv4Addr::LOCALHOST.octets(), port);
    // The host's real addresses: 127.0.0.1 is local, and the default-route
    // address, whatever it is, must not win over the own row.
    let mut bbmd = wildcard_bbmd(
        port,
        vec![
            row(Ipv4Addr::LOCALHOST, port),
            row(Ipv4Addr::LOCALHOST, port_of(&bdt_peer)),
        ],
        None,
    );
    let mut rx = bbmd.start().await.unwrap();

    assert_eq!(bbmd.local_mac(), encode_bip_mac(own.0, own.1));
    {
        let state = bbmd.bbmd_state().unwrap().lock().await;
        assert_eq!(state.local_address(), own);
        assert_eq!(state.bdt().len(), 2, "no second self row");
    }

    bbmd.send_broadcast(NPDU).await.unwrap();
    assert_own_forwarded(&recv_bvll(&bdt_peer).await, own, "BDT peer");
    // The local copy comes back from 127.0.0.1, the local MAC, so it is dropped
    // as the echo rather than delivered and forwarded a second time.
    assert!(
        tokio::time::timeout(Duration::from_millis(100), rx.recv())
            .await
            .is_err(),
        "own broadcast echo must not be delivered"
    );
    assert_no_bvll(&bdt_peer, "BDT peer").await;
    bbmd.stop().await.unwrap();
}

#[tokio::test]
async fn wildcard_bbmd_with_several_own_rows_fails_start_and_keeps_its_config() {
    let port = free_port();
    let mut bbmd = wildcard_bbmd(
        port,
        vec![row(Ipv4Addr::LOCALHOST, port), row(LAN, port)],
        Some((vec![Ipv4Addr::LOCALHOST, LAN], Some(LAN))),
    );

    let err = bbmd.start().await.unwrap_err();

    let text = err.to_string();
    assert!(
        text.contains("several local IPv4 addresses")
            && text.contains("bind an explicit interface address"),
        "{text}"
    );
    assert!(bbmd.socket.is_none() && bbmd.recv_task.is_none());
    assert!(bbmd.bbmd.is_none());
    assert!(
        bbmd.bbmd_config.is_some(),
        "a failed start keeps the BBMD configuration"
    );
    assert_eq!(bbmd.local_mac(), [0; 6]);
}

#[tokio::test]
async fn wildcard_bbmd_without_own_row_or_usable_route_fails_start() {
    for route in [None, Some(Ipv4Addr::LOCALHOST)] {
        let mut bbmd = wildcard_bbmd(
            0,
            vec![row(REMOTE_PEER, PORT)],
            Some((vec![Ipv4Addr::LOCALHOST], route)),
        );
        let text = bbmd.start().await.unwrap_err().to_string();
        assert!(
            text.contains("cannot determine its own B/IP address")
                && text.contains("add this BBMD's own row to the BDT"),
            "{route:?}: {text}"
        );
        assert!(bbmd.bbmd.is_none() && bbmd.bbmd_config.is_some());
    }
}

#[tokio::test]
async fn wildcard_bbmd_reads_its_own_row_from_the_persisted_bdt() {
    let port = free_port();
    let path = std::env::temp_dir().join(format!(
        "rusty-bacnet-own-row-{}-{port}.bdt",
        std::process::id()
    ));
    let mut seed = BytesMut::new();
    bbmd::encode_bdt_entries(&[row(Ipv4Addr::LOCALHOST, port)], &mut seed);
    std::fs::write(&path, &seed).unwrap();
    // The configured BDT names the other local address; the persisted BDT is
    // the one the BBMD runs with, so its row decides.
    let mut bbmd = wildcard_bbmd(
        port,
        vec![row(LAN, port)],
        Some((vec![Ipv4Addr::LOCALHOST, LAN], Some(LAN))),
    );
    bbmd.set_bdt_persist_path(path.clone());

    let started = bbmd.start().await;
    let _ = std::fs::remove_file(&path);
    let _rx = started.unwrap();

    assert_eq!(
        bbmd.local_mac(),
        encode_bip_mac(Ipv4Addr::LOCALHOST.octets(), port)
    );
    let bdt = bbmd.bbmd_state().unwrap().lock().await.bdt().to_vec();
    assert_eq!(bdt, vec![row(Ipv4Addr::LOCALHOST, port)]);
    bbmd.stop().await.unwrap();
}

#[tokio::test]
async fn restart_chooses_the_bbmd_address_again_and_drops_the_stale_self_row() {
    let bdt_peer = udp().await;
    let foreign = udp().await;
    let port = free_port();
    let peer_row = row(Ipv4Addr::LOCALHOST, port_of(&bdt_peer));
    let loopback_row = row(Ipv4Addr::LOCALHOST, port);
    // First start: 127.0.0.1 is not among the host's addresses, so no row is
    // the BBMD's own and the default-route address LAN is used.
    let mut bbmd = wildcard_bbmd(
        port,
        vec![peer_row.clone(), loopback_row.clone()],
        Some((vec![LAN], Some(LAN))),
    );
    bbmd.enable_foreign_device_registration(ForeignDevicePolicy::default());
    let _rx = bbmd.start().await.unwrap();
    assert_eq!(bbmd.local_mac(), encode_bip_mac(LAN.octets(), port));
    {
        let mut state = bbmd.bbmd_state().unwrap().lock().await;
        assert_eq!(
            state.bdt(),
            &[peer_row.clone(), loopback_row.clone(), row(LAN, port)]
        );
        assert_eq!(
            state.register_foreign_device([127, 0, 0, 1], port_of(&foreign), 60),
            BvlcResultCode::SUCCESSFUL_COMPLETION
        );
    }
    bbmd.stop().await.unwrap();

    // Restart: now 127.0.0.1 is local, so its row is the BBMD's own.
    bbmd.local_ipv4_for_test = Some((vec![Ipv4Addr::LOCALHOST, LAN], Some(LAN)));
    let mut rx = bbmd.start().await.unwrap();
    let own = (Ipv4Addr::LOCALHOST.octets(), port);
    assert_eq!(bbmd.local_mac(), encode_bip_mac(own.0, own.1));
    {
        let mut state = bbmd.bbmd_state().unwrap().lock().await;
        assert_eq!(state.local_address(), own);
        // The self row appended for LAN is gone, not left behind as a peer.
        assert_eq!(state.bdt(), &[peer_row, loopback_row]);
        assert_eq!(state.fdt().len(), 1, "the FDT survives the restart");
    }

    bbmd.send_broadcast(NPDU).await.unwrap();
    assert_own_forwarded(&recv_bvll(&bdt_peer).await, own, "BDT peer");
    assert_own_forwarded(&recv_bvll(&foreign).await, own, "foreign device");
    assert!(
        tokio::time::timeout(Duration::from_millis(100), rx.recv())
            .await
            .is_err(),
        "own broadcast echo must not be delivered"
    );
    assert_no_bvll(&bdt_peer, "BDT peer").await;
    assert_no_bvll(&foreign, "foreign device").await;
    bbmd.stop().await.unwrap();
}
