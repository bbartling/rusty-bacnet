//! Event_Message_Texts_Config and the Event_Algorithm_Inhibit pair through
//! the server's evaluation paths (#1329): a configured text is the Message
//! Text sent and stored, and the inhibit follows its reference each time
//! the object is evaluated, on a write and on the one-second tick.

use super::*;
use bacnet_encoding::constructed::encode_object_property_reference;
use bacnet_objects::binary::BinaryValueObject;
use bacnet_types::constructed::BACnetObjectPropertyReference;
use bytes::BytesMut;

fn ai() -> ObjectIdentifier {
    ObjectIdentifier::new(ObjectType::ANALOG_INPUT, 1).unwrap()
}

fn switch() -> ObjectIdentifier {
    ObjectIdentifier::new(ObjectType::BINARY_VALUE, 1).unwrap()
}

fn texts(texts: [&str; 3]) -> PropertyValue {
    PropertyValue::List(
        texts
            .map(|text| PropertyValue::CharacterString(text.into()))
            .to_vec(),
    )
}

fn reference_to_switch() -> PropertyValue {
    let mut octets = BytesMut::new();
    encode_object_property_reference(
        &mut octets,
        &BACnetObjectPropertyReference::new(switch(), PropertyIdentifier::PRESENT_VALUE.to_raw()),
    );
    PropertyValue::ApplicationData(octets.to_vec())
}

fn event_state(db: &ObjectDatabase) -> PropertyValue {
    db.get(&ai())
        .unwrap()
        .read_property(PropertyIdentifier::EVENT_STATE, None)
        .unwrap()
}

/// The high-limit fixture with a Binary Value at `active` its inhibit
/// follows.
async fn inhibited_fixture(active: bool) -> Arc<tokio::sync::RwLock<ObjectDatabase>> {
    let db = db_with_high_limit_transition(0x80);
    {
        let mut db = db.write().await;
        let mut bv = BinaryValueObject::new(1, "BV-1").unwrap();
        bv.write_property_from(
            PropertyIdentifier::PRESENT_VALUE,
            None,
            PropertyValue::Enumerated(u32::from(active)),
            Some(8),
            &crate::command_source::test_origin(),
        )
        .unwrap();
        db.add(Box::new(bv)).unwrap();
        db.get_mut(&ai())
            .unwrap()
            .write_property(
                PropertyIdentifier::EVENT_ALGORITHM_INHIBIT_REF,
                None,
                reference_to_switch(),
                None,
            )
            .unwrap();
    }
    db
}

#[tokio::test]
async fn a_configured_message_text_is_the_one_sent_and_stored() {
    let db = db_with_high_limit_transition(0x80);
    db.write()
        .await
        .get_mut(&ai())
        .unwrap()
        .write_property(
            PropertyIdentifier::EVENT_MESSAGE_TEXTS_CONFIG,
            None,
            texts(["Too hot", "", ""]),
            None,
        )
        .unwrap();
    let sent = broadcasts_from_per_write_path(&db, DccState::Enable).await;
    let notification = decode_broadcast_notification(&sent);
    assert_eq!(notification.message_text, Some("Too hot".into()));
    assert_eq!(
        db.read()
            .await
            .get(&ai())
            .unwrap()
            .read_property(PropertyIdentifier::EVENT_MESSAGE_TEXTS, Some(1))
            .unwrap(),
        PropertyValue::CharacterString("Too hot".into())
    );
}

#[tokio::test]
async fn the_write_path_follows_the_reference_before_it_evaluates() {
    // ACTIVE: inhibited, so the high value goes unreported.
    let db = inhibited_fixture(true).await;
    let sent = broadcasts_from_per_write_path(&db, DccState::Enable).await;
    assert!(sent.is_empty(), "an inhibited algorithm reports nothing");
    {
        let db = db.read().await;
        assert_eq!(
            db.get(&ai())
                .unwrap()
                .read_property(PropertyIdentifier::EVENT_ALGORITHM_INHIBIT, None)
                .unwrap(),
            PropertyValue::Boolean(true)
        );
        assert_eq!(
            event_state(&db),
            PropertyValue::Enumerated(EventState::NORMAL.to_raw())
        );
    }
    // INACTIVE: the next evaluation follows it and reports.
    db.write()
        .await
        .get_mut(&switch())
        .unwrap()
        .write_property_from(
            PropertyIdentifier::PRESENT_VALUE,
            None,
            PropertyValue::Enumerated(0),
            Some(8),
            &crate::command_source::test_origin(),
        )
        .unwrap();
    let sent = broadcasts_from_per_write_path(&db, DccState::Enable).await;
    assert_eq!(
        decode_broadcast_notification(&sent).to_state,
        EventState::HIGH_LIMIT
    );
}

#[tokio::test(start_paused = true)]
async fn the_tick_follows_the_reference_within_a_second() {
    let (transport, sent) = recording_transport();
    let Ok(db) = Arc::try_unwrap(inhibited_fixture(true).await) else {
        panic!("the fixture holds the only handle");
    };
    let db = db.into_inner();
    let server = BACnetServer::start(ServerConfig::default(), db, transport)
        .await
        .expect("server should start");
    tokio::time::sleep(Duration::from_secs(3)).await;
    assert!(sent.is_empty(), "inhibited while the switch is ACTIVE");

    // The switch's own write evaluates only the switch; the Analog Input
    // picks the change up on its next tick.
    server
        .write_local(
            &switch(),
            PropertyIdentifier::PRESENT_VALUE,
            None,
            PropertyValue::Enumerated(0),
            Some(8),
            crate::LocalCommandSource::ServerDevice,
        )
        .await
        .expect("local write should succeed");
    tokio::time::sleep(Duration::from_secs(3)).await;
    assert_eq!(
        decode_broadcast_notification(&sent.npdus()).to_state,
        EventState::HIGH_LIMIT
    );

    // ACTIVE again: the tick brings the input back to NORMAL at once.
    server
        .write_local(
            &switch(),
            PropertyIdentifier::PRESENT_VALUE,
            None,
            PropertyValue::Enumerated(1),
            Some(8),
            crate::LocalCommandSource::ServerDevice,
        )
        .await
        .expect("local write should succeed");
    tokio::time::sleep(Duration::from_secs(2)).await;
    assert_eq!(
        event_state(&*server.database().read().await),
        PropertyValue::Enumerated(EventState::NORMAL.to_raw())
    );
}
