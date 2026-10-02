//! A client from `sc_builder` lends its transport's connection-state watch and
//! NPDU drop counts against an in-process mTLS hub (#956).
use bacnet_benchmarks::sc_helpers::*;
use bacnet_client::client::BACnetClient;
use bacnet_transport::sc::{ScConnectionState, ScNpduDropCounts};
use std::{future::Future, time::Duration};

async fn bounded<T>(future: impl Future<Output = T>) -> T {
    tokio::time::timeout(Duration::from_secs(5), future)
        .await
        .expect("SC client handle step timed out")
}

#[tokio::test]
async fn sc_builder_client_lends_a_watch_that_observes_connected() {
    let certs = generate_test_certs();
    let (mut hub, url) = start_sc_hub_mtls(&certs, [0x02, 0, 0, 0, 0, 0x10]).await;
    let mut client = bounded(Box::pin(
        BACnetClient::sc_builder()
            .hub_url(&url)
            .tls_config(try_make_node_tls_config(&certs).unwrap())
            .vmac([0x02, 0, 0, 0, 0, 0x21])
            .device_uuid([0x21; 16])
            .apdu_timeout_ms(2000)
            .build(),
    ))
    .await
    .unwrap();

    // The receiver is owned, so a UI can await it in a task of its own.
    let mut state = client.transport().connection_state_changes();
    let watcher = tokio::spawn(async move {
        state
            .wait_for(|now| *now == ScConnectionState::Connected)
            .await
            .map(|seen| *seen)
    });
    assert_eq!(
        bounded(watcher).await.unwrap().unwrap(),
        ScConnectionState::Connected
    );
    // Drop counts are a snapshot to poll; nothing has been dropped yet.
    assert_eq!(
        client.transport().npdu_drop_counts(),
        ScNpduDropCounts::default()
    );

    bounded(client.stop()).await.unwrap();
    bounded(hub.stop()).await;
}
