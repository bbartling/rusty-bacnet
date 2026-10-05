//! An Address recipient naming this device's own network number is local
//! once the server knows that number (#1460), as a Notification Class
//! recipient's is (#1358): records go to its MAC with no DNET. While the
//! number is unknown it names a routed station, which target Audit does not
//! route, so it waits unresolved, reporting CONFIGURATION_ERROR as a Device
//! with no route does, and resolves from the first record after the number
//! is learned. When the number moves away, it no longer resolves, and a
//! recipient change goes ahead with no copy for it.
use super::*;

/// The link's B/IP broadcast endpoint.
const BROADCAST: std::net::SocketAddrV4 =
    std::net::SocketAddrV4::new(std::net::Ipv4Addr::new(10, 0, 0, 255), 0xBAC0);
/// The logger at the recipient address, and the one a change moves to.
const STATION: [u8; 6] = [10, 0, 0, 2, 0xBA, 0xC0];
const NEW_STATION: [u8; 6] = [10, 0, 0, 4, 0xBA, 0xC0];

fn address(network: u16, mac: &[u8]) -> BACnetRecipient {
    BACnetRecipient::Address(BACnetAddress {
        network_number: network,
        mac_address: MacAddr::from_slice(mac),
    })
}

/// A started B/IP-shaped server whose Device 10 reports WRITE operations
/// to `recipient`, confirmed or not, and has not learned its number.
async fn address_logger(recipient: BACnetRecipient, confirmed: bool) -> Result<Fixture, Error> {
    let mut reporter = reporter();
    reporter
        .set_issue_confirmed_notifications(confirmed)
        .unwrap();
    try_servers_config(
        vec![reporter],
        &[10],
        Some(recipient),
        vec![],
        true,
        1476,
        bip_capture(),
    )
    .await
}

/// A B/IP-shaped capture link, with a broadcast endpoint.
fn bip_capture() -> AuditCapture {
    let mut capture = AuditCapture::default();
    capture.six_byte_mac = true;
    capture.bip_broadcast = Some(BROADCAST);
    capture
}

/// Where each record went: its link MAC, and whether the NPDU had a DNET.
fn sends(fixture: &Fixture) -> Vec<(Vec<u8>, bool)> {
    let macs = fixture.transport.destinations.lock().unwrap().clone();
    let sent = fixture.transport.sent.lock().unwrap().clone();
    macs.into_iter()
        .zip(sent)
        .map(|(mac, bytes)| (mac, decode_npdu(bytes).unwrap().destination.is_some()))
        .collect()
}

/// Change Device 10's Audit_Notification_Recipient as the application.
async fn change_recipient(fixture: &Fixture, recipient: &BACnetRecipient) -> Result<(), Error> {
    let mut bytes = BytesMut::new();
    bacnet_encoding::constructed::encode_recipient(&mut bytes, recipient).unwrap();
    fixture
        .server
        .write_local(
            &oid(ObjectType::DEVICE, 10),
            PropertyIdentifier::AUDIT_NOTIFICATION_RECIPIENT,
            None,
            PropertyValue::ApplicationData(bytes.to_vec()),
            None,
            crate::LocalCommandSource::ServerDevice,
        )
        .await
}

#[tokio::test(start_paused = true)]
async fn an_address_recipient_on_this_network_waits_for_the_number_then_goes_without_a_dnet() {
    let mut fixture = address_logger(address(THIS_NETWORK, &STATION), true)
        .await
        .expect("starts unresolved while the number is unknown");
    assert_eq!(
        health(&fixture.server).await,
        Reliability::CONFIGURATION_ERROR
    );
    // Unknown number: nothing goes out, and the write still succeeds.
    assert!(matches!(
        write_value(&fixture.server, None).await,
        Apdu::SimpleAck(_)
    ));
    settle().await;
    assert!(sends(&fixture).is_empty());
    assert_eq!(
        health(&fixture.server).await,
        Reliability::CONFIGURATION_ERROR
    );
    // Known: the record goes straight to the station, and its ACK from
    // there with no SNET completes it.
    publish(&fixture, THIS_NETWORK);
    assert!(matches!(
        write_value(&fixture.server, None).await,
        Apdu::SimpleAck(_)
    ));
    settle().await;
    assert_eq!(sends(&fixture), [(STATION.to_vec(), false)]);
    let request = confirmed_notification(&fixture.transport.sent, 0);
    assert!(fixture.server.notification_transactions.admit_terminal(
        &STATION,
        None,
        None,
        &Apdu::SimpleAck(SimpleAck {
            invoke_id: request.invoke_id,
            service_choice: request.service_choice,
        }),
    ));
    settle().await;
    assert_eq!(fixture.server.notification_transactions.active_count(), 0);
    assert_eq!(
        health(&fixture.server).await,
        Reliability::NO_FAULT_DETECTED
    );
    // Another number: the address is off this network again.
    publish(&fixture, REMOTE_NETWORK);
    assert!(matches!(
        write_value(&fixture.server, None).await,
        Apdu::SimpleAck(_)
    ));
    settle().await;
    assert_eq!(sends(&fixture).len(), 1, "no record off this network");
    assert_eq!(
        health(&fixture.server).await,
        Reliability::CONFIGURATION_ERROR
    );
    fixture.server.stop().await.unwrap();
}

#[tokio::test(start_paused = true)]
async fn a_change_away_from_an_address_the_number_left_goes_to_the_new_recipient_only() {
    let mut fixture = address_logger(address(THIS_NETWORK, &STATION), false)
        .await
        .unwrap();
    // While the number is unknown, a new address on it has no route either.
    assert!(
        change_recipient(&fixture, &address(THIS_NETWORK, &NEW_STATION))
            .await
            .is_err()
    );
    publish(&fixture, THIS_NETWORK);
    publish(&fixture, REMOTE_NETWORK);
    // The old address no longer resolves; the change still goes ahead, and
    // only the new recipient gets its record.
    let next = address(0, &NEW_STATION);
    change_recipient(&fixture, &next).await.unwrap();
    settle().await;
    assert_eq!(sends(&fixture), [(NEW_STATION.to_vec(), false)]);
    let records = notifications(&fixture.transport.sent);
    assert_eq!(records.len(), 1);
    let record = &records[0].notifications[0];
    assert_eq!(record.operation, AuditOperation::WRITE);
    let mut old = BytesMut::new();
    bacnet_encoding::constructed::encode_recipient(&mut old, &address(THIS_NETWORK, &STATION))
        .unwrap();
    assert_eq!(record.current_value.as_deref(), Some(&old[..]));
    // Ordinary records follow the new recipient.
    assert!(matches!(
        write_value(&fixture.server, None).await,
        Apdu::SimpleAck(_)
    ));
    settle().await;
    assert_eq!(sends(&fixture).len(), 2);
    assert_eq!(sends(&fixture)[1], (NEW_STATION.to_vec(), false));
    assert_eq!(
        health(&fixture.server).await,
        Reliability::NO_FAULT_DETECTED
    );
    fixture.server.stop().await.unwrap();
}

#[tokio::test(start_paused = true)]
async fn a_change_away_from_a_device_with_no_route_is_still_refused() {
    // Only an Address the number moved away from is passed over: an old
    // Device recipient with no route still holds a change up.
    let mut fixture = try_servers_config(
        vec![reporter()],
        &[10],
        Some(BACnetRecipient::Device(oid(ObjectType::DEVICE, 999))),
        vec![],
        true,
        1476,
        bip_capture(),
    )
    .await
    .unwrap();
    publish(&fixture, THIS_NETWORK);
    assert!(change_recipient(&fixture, &address(0, &NEW_STATION))
        .await
        .is_err());
    settle().await;
    assert!(sends(&fixture).is_empty());
    fixture.server.stop().await.unwrap();
}
