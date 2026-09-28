use super::*;

#[tokio::test]
async fn registration_token_follows_last_socket_worker_after_abort() {
    let token = Arc::new(());
    let weak = Arc::downgrade(&token);
    let mut transport = BipTransport::new(Ipv4Addr::LOCALHOST, 0, Ipv4Addr::BROADCAST);
    transport.retain_network_port_lease_internal(token).unwrap();
    assert!(transport
        .retain_network_port_lease_internal(Arc::new(()))
        .is_err());
    let _received = transport.start().await.unwrap();
    let address = transport.normal_bip_endpoint().unwrap();
    assert_ne!(address.port(), 0);
    let socket = transport.socket.as_ref().unwrap().clone();
    // Transport, receive, fanout and this held worker all share the same owner.
    assert!(Arc::strong_count(&socket) >= 4);
    let (release, held) = oneshot::channel::<()>();
    let worker = tokio::spawn(async move {
        let _ = held.await;
        drop(socket);
    });
    let aborted = transport.abort_background_tasks();
    drop(transport);
    for task in aborted {
        let _ = task.await;
    }
    assert!(weak.upgrade().is_some());
    assert!(std::net::UdpSocket::bind(address).is_err());
    release.send(()).unwrap();
    worker.await.unwrap();
    assert!(weak.upgrade().is_none());
    let _reused = std::net::UdpSocket::bind(address).unwrap();
}

#[tokio::test]
async fn normal_capability_and_joined_stop_release_are_explicit() {
    let mut transport = BipTransport::new(Ipv4Addr::LOCALHOST, 0, Ipv4Addr::BROADCAST);
    assert!(transport.supports_local_nonrouter_number_controls());
    let token = Arc::new(());
    let weak = Arc::downgrade(&token);
    transport.retain_network_port_lease_internal(token).unwrap();
    let _received = transport.start().await.unwrap();
    assert!(transport.supports_local_nonrouter_number_controls());
    assert!(transport
        .retain_network_port_lease_internal(Arc::new(()))
        .is_err());
    transport.stop().await.unwrap();
    assert!(weak.upgrade().is_none());
    assert!(transport
        .retain_network_port_lease_internal(Arc::new(()))
        .is_err());
    let mut bbmd = BipTransport::new(Ipv4Addr::LOCALHOST, 0, Ipv4Addr::BROADCAST);
    bbmd.enable_bbmd(vec![]);
    assert!(!bbmd.supports_local_nonrouter_number_controls());
    assert!(bbmd.normal_bip_endpoint().is_none());
    assert!(bbmd
        .retain_network_port_lease_internal(Arc::new(()))
        .is_err());
    let _received = bbmd.start().await.unwrap();
    assert!(!bbmd.supports_local_nonrouter_number_controls());
    assert!(bbmd.normal_bip_endpoint().is_none());
    bbmd.stop().await.unwrap();
    let mut foreign = BipTransport::new(Ipv4Addr::LOCALHOST, 0, Ipv4Addr::BROADCAST);
    foreign.register_as_foreign_device(ForeignDeviceConfig {
        bbmd_ip: Ipv4Addr::LOCALHOST,
        bbmd_port: 47808,
        ttl: 60,
    });
    assert!(!foreign.supports_local_nonrouter_number_controls());
    assert!(foreign.normal_bip_endpoint().is_none());
    assert!(foreign
        .retain_network_port_lease_internal(Arc::new(()))
        .is_err());
}
