//! Audit notifications to a Device recipient whose configured binding is
//! routed through this device's own network number go to the recipient's MAC
//! with no DNET, and its ACK from there, with no SNET, completes them (#1358).
//! The route is taken again for each notification, so a number published
//! after startup applies from the next one on, a reporter's change to its own
//! properties included.
//!
//! Device 20 is the recipient, `LOGGER` on the network a test names, reached
//! through `NEW_LOGGER` as its router. The number is published on the
//! server's layer as its Number worker would.
use super::*;
use bacnet_types::network_number::NetworkNumber;

/// The number of the network this device is attached to.
pub(super) const THIS_NETWORK: u16 = 7;
pub(super) const REMOTE_NETWORK: u16 = 5;

/// A reporter whose notifications are confirmed, so each one shows which
/// peer its ACK has to come from.
fn confirmed_reporter() -> bacnet_objects::audit::AuditReporterObject {
    let mut reporter = reporter();
    reporter.set_issue_confirmed_notifications(true).unwrap();
    reporter
}

/// A server whose Device 10 reports to Device 20, bound at `LOGGER` on
/// `network` behind `NEW_LOGGER`.
async fn routed_logger(network: u16) -> Fixture {
    try_server(
        confirmed_reporter(),
        &[10],
        Some(BACnetRecipient::Device(oid(ObjectType::DEVICE, 20))),
        vec![
            DeviceBinding::routed(oid(ObjectType::DEVICE, 20), network, LOGGER, NEW_LOGGER)
                .unwrap(),
        ],
    )
    .await
    .unwrap()
}

/// Publish `number` as this network's own, as the server's Number worker
/// would.
pub(super) fn publish(fixture: &Fixture, number: u16) {
    fixture
        .server
        .test_network()
        .local_network_number()
        .publish(NetworkNumber::configured(number).unwrap());
}

/// Where each notification went, in order: the link MAC and the DNET. A
/// routed one always names `LOGGER` as its DADR.
fn routes(fixture: &Fixture) -> Vec<(Vec<u8>, Option<u16>)> {
    let macs = fixture.transport.destinations.lock().unwrap().clone();
    let sent = fixture.transport.sent.lock().unwrap().clone();
    macs.into_iter()
        .zip(sent)
        .map(|(mac, bytes)| {
            let dnet = decode_npdu(bytes).unwrap().destination.map(|to| {
                assert_eq!(to.mac_address.as_slice(), LOGGER);
                to.network
            });
            (mac, dnet)
        })
        .collect()
}

/// Acknowledge notification `index` the way the recipient's answer comes
/// back: from its own MAC for a local copy, from the router with the
/// recipient's SNET otherwise. Whether the ACK completed it.
fn acknowledge(fixture: &Fixture, index: usize) -> bool {
    let request = confirmed_notification(&fixture.transport.sent, index);
    let (mac, dnet) = routes(fixture).swap_remove(index);
    let source = dnet.map(|network| NpduAddress {
        network,
        mac_address: MacAddr::from_slice(LOGGER),
    });
    fixture.server.notification_transactions.admit_terminal(
        &mac,
        source.as_ref(),
        &Apdu::SimpleAck(SimpleAck {
            invoke_id: request.invoke_id,
            service_choice: request.service_choice,
        }),
    )
}

/// Write the reporter's own Description, a change it reports through the
/// route to its current recipient.
async fn change_reporter(fixture: &Fixture) {
    let response = dispatch(
        &fixture.server,
        ConfirmedServiceChoice::WRITE_PROPERTY,
        wp(
            oid(ObjectType::AUDIT_REPORTER, 1),
            PropertyIdentifier::DESCRIPTION,
            vec![0x72, 0, 0x78],
            None,
        ),
    )
    .await;
    assert!(matches!(response, Apdu::SimpleAck(_)), "{response:?}");
}

#[tokio::test(start_paused = true)]
async fn audit_notifications_to_a_binding_routed_through_this_network_go_without_a_dnet() {
    let mut fixture = routed_logger(THIS_NETWORK).await;
    // While the number is unknown the binding is taken as configured.
    write_value(&fixture.server, None).await;
    settle().await;
    assert!(acknowledge(&fixture, 0));
    publish(&fixture, THIS_NETWORK);
    write_value(&fixture.server, None).await;
    settle().await;
    assert!(acknowledge(&fixture, 1));
    change_reporter(&fixture).await;
    settle().await;
    assert!(acknowledge(&fixture, 2));
    assert_eq!(
        routes(&fixture),
        [
            (NEW_LOGGER.to_vec(), Some(THIS_NETWORK)),
            (LOGGER.to_vec(), None),
            (LOGGER.to_vec(), None),
        ]
    );
    assert_eq!(fixture.server.notification_transactions.active_count(), 0);
    assert_eq!(
        health(&fixture.server).await,
        Reliability::NO_FAULT_DETECTED
    );
    fixture.server.stop().await.unwrap();
}

#[tokio::test(start_paused = true)]
async fn audit_notifications_to_a_binding_routed_to_another_network_keep_its_dnet() {
    let mut fixture = routed_logger(REMOTE_NETWORK).await;
    publish(&fixture, THIS_NETWORK);
    write_value(&fixture.server, None).await;
    settle().await;
    assert!(acknowledge(&fixture, 0));
    change_reporter(&fixture).await;
    settle().await;
    assert!(acknowledge(&fixture, 1));
    assert_eq!(
        routes(&fixture),
        [
            (NEW_LOGGER.to_vec(), Some(REMOTE_NETWORK)),
            (NEW_LOGGER.to_vec(), Some(REMOTE_NETWORK)),
        ]
    );
    assert_eq!(
        health(&fixture.server).await,
        Reliability::NO_FAULT_DETECTED
    );
    fixture.server.stop().await.unwrap();
}
