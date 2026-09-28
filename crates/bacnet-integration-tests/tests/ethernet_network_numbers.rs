//! Opt-in actual Linux Ethernet fixture; requires an isolated peer and NET_RAW.
#![cfg(all(target_os = "linux", feature = "ethernet"))]
use bacnet_client::client::{BACnetClient, ClientConfig};
use bacnet_objects::{database::ObjectDatabase, network_port::NetworkPortObject};
use bacnet_server::server::{BACnetServer, ServerConfig};
use bacnet_transport::{
    any::AnyTransport, ethernet::EthernetTransport, mstp::LoopbackSerial, port::TransportPort,
};
use bacnet_types::{enums::NetworkType, MacAddr};
use std::{future::Future, path::PathBuf, time::Duration};

fn interface() -> String {
    std::env::var("BACNET_ETHERNET_INTERFACE").expect("explicit isolated interface")
}
fn raw_sockets() -> usize {
    // Count this test process's packet FDs, excluding namespace daemons/peers.
    let packet_inodes: std::collections::HashSet<_> = std::fs::read_to_string("/proc/net/packet")
        .unwrap()
        .lines()
        .skip(1)
        .filter_map(|row| {
            row.split_whitespace()
                .last()
                .map(|inode| format!("socket:[{inode}]"))
        })
        .collect();
    std::fs::read_dir("/proc/self/fd")
        .unwrap()
        .filter_map(|entry| std::fs::read_link(entry.ok()?.path()).ok())
        .filter(|link| packet_inodes.contains(link.to_string_lossy().as_ref()))
        .count()
}

async fn wait_for(mut predicate: impl FnMut() -> bool) {
    tokio::time::timeout(Duration::from_secs(30), async {
        while !predicate() {
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    })
    .await
    .expect("isolated Ethernet fixture made no progress");
}
#[tokio::test]
#[ignore = "requires explicit isolated Linux interface and CAP_NET_RAW"]
async fn ethernet_transport_drop_releases_socket() {
    let before = raw_sockets();
    let mut transport = EthernetTransport::new(&interface());
    let mut received = transport.start().await.unwrap();
    assert_eq!(raw_sockets(), before + 1);
    drop(transport);
    assert!(
        tokio::time::timeout(Duration::from_secs(2), received.recv())
            .await
            .expect("drop must close receive owner")
            .is_none()
    );
    assert_eq!(raw_sockets(), before);
}
#[tokio::test]
#[ignore = "requires explicit isolated Linux interface and CAP_NET_RAW"]
async fn ethernet_transport_cancelled_stop_joins_before_return() {
    let before = raw_sockets();
    let mut transport = EthernetTransport::new(&interface());
    let mut received = transport.start().await.unwrap();
    {
        let stop = transport.stop();
        tokio::pin!(stop);
        // Poll once on this current-thread runtime: abort starts, join is pending.
        assert!(
            std::future::poll_fn(|cx| std::task::Poll::Ready(stop.as_mut().poll(cx)))
                .await
                .is_pending()
        );
    }
    transport.stop().await.unwrap();
    assert_eq!(
        raw_sockets(),
        before,
        "completed stop must join the raw-fd owner"
    );
    assert!(received.recv().await.is_none());
}

#[tokio::test]
#[ignore = "requires isolated Linux raw peer; see ethernet_network_numbers/README.md"]
async fn ethernet_number_full_server_and_client_wire() {
    let directory = PathBuf::from(
        std::env::var("BACNET_ETHERNET_FIXTURE_DIR").expect("peer coordination directory"),
    );
    let before = raw_sockets();
    for case in ["server-stop", "server-drop", "client-stop", "client-drop"] {
        let transport: AnyTransport<LoopbackSerial> =
            AnyTransport::Ethernet(EthernetTransport::new(&interface()));
        assert!(transport.normal_bip_endpoint().is_none());
        let is_server = case.starts_with("server");
        let (mut server, mut client) = if is_server {
            let mut db = ObjectDatabase::new();
            db.add(Box::new(
                NetworkPortObject::new_non_bip(
                    9,
                    "unrelated configured Ethernet",
                    NetworkType::ETHERNET,
                    999,
                    MacAddr::from_slice(&[2, 0, 0, 0, 0, 9]),
                    1476,
                )
                .unwrap(),
            ))
            .unwrap();
            (
                Some(
                    BACnetServer::start(ServerConfig::default(), db, transport)
                        .await
                        .unwrap(),
                ),
                None,
            )
        } else {
            (
                None,
                Some(
                    BACnetClient::start(ClientConfig::default(), transport)
                        .await
                        .unwrap(),
                ),
            )
        };
        let mac = if let Some(server) = &server {
            server.local_mac()
        } else {
            client.as_ref().unwrap().local_mac()
        };
        let ready = serde_json::json!({"case":case,"mac":mac,"raw_sockets":raw_sockets()});
        let temporary = directory.join(format!("{case}.tmp"));
        std::fs::write(&temporary, ready.to_string()).unwrap();
        std::fs::rename(temporary, directory.join(format!("{case}.ready"))).unwrap();
        wait_for(|| {
            directory.join(format!("{case}.done")).exists() || directory.join("peer.error").exists()
        })
        .await;
        assert!(
            !directory.join("peer.error").exists(),
            "independent peer assertions failed"
        );
        if case.ends_with("stop") {
            if let Some(server) = &mut server {
                server.stop().await.unwrap();
            }
            if let Some(client) = &mut client {
                client.stop().await.unwrap();
            }
            assert_eq!(
                raw_sockets(),
                before,
                "stop releases raw FD before owner drop"
            );
        }
        drop(server);
        drop(client);
        wait_for(|| raw_sockets() == before).await;
        std::fs::write(
            directory.join(format!("{case}.stopped")),
            b"raw_fds_released",
        )
        .unwrap();
        wait_for(|| directory.join(format!("{case}.checked")).exists()).await;
    }
}
