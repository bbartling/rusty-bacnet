use super::*;
use bacnet_objects::notification_class::NotificationClass;
use bacnet_types::{
    bitstring::{DaysOfWeek, EventTransitionBits},
    constructed::BACnetDestination,
    primitives::Time,
};

#[tokio::test]
async fn audit_empty_values_wp_recipient_list_preserves_present_empty_and_null() {
    let mut fixture = server(reporter()).await;
    let target = oid(ObjectType::NOTIFICATION_CLASS, 1);
    let destination = BACnetDestination {
        valid_days: DaysOfWeek::all(),
        from_time: Time {
            hour: 0,
            minute: 0,
            second: 0,
            hundredths: 0,
        },
        to_time: Time {
            hour: 23,
            minute: 59,
            second: 0,
            hundredths: 0,
        },
        recipient: BACnetRecipient::Device(oid(ObjectType::DEVICE, 20)),
        process_identifier: 1,
        issue_confirmed_notifications: false,
        transitions: EventTransitionBits::all(),
    };
    let mut populated = BytesMut::new();
    bacnet_encoding::constructed::encode_destination_list(
        &mut populated,
        std::slice::from_ref(&destination),
    );
    assert!(populated.len() <= 32);
    let mut object = NotificationClass::new(1, "empty-audit-destinations").unwrap();
    object.add_destination(destination);
    fixture
        .server
        .db
        .write()
        .await
        .add(Box::new(object))
        .unwrap();
    for (index, previous) in [populated.to_vec(), vec![]].into_iter().enumerate() {
        let response = dispatch(
            &fixture.server,
            ConfirmedServiceChoice::WRITE_PROPERTY,
            wp(target, PropertyIdentifier::RECIPIENT_LIST, vec![], None),
        )
        .await;
        assert!(matches!(response, Apdu::SimpleAck(_)), "{response:?}");
        assert_eq!(
            fixture
                .server
                .db
                .read()
                .await
                .get(&target)
                .unwrap()
                .read_property(PropertyIdentifier::RECIPIENT_LIST, None)
                .unwrap(),
            PropertyValue::ApplicationData(vec![])
        );
        settle().await;
        let records = notifications(&fixture.transport.sent);
        assert_eq!(records.len(), index + 1);
        assert_eq!(records[index].notifications.len(), 1);
        let record = &records[index].notifications[0];
        assert_eq!(record.operation, AuditOperation::WRITE);
        assert_eq!(record.invoke_id, Some(77 + index as u8));
        assert_eq!(record.target_object, Some(target));
        assert_eq!(
            record.target_property,
            Some(AuditPropertyReference {
                property_identifier: PropertyIdentifier::RECIPIENT_LIST,
                property_array_index: None
            })
        );
        assert_eq!(record.target_value, Some(vec![]));
        assert_eq!(record.current_value, Some(previous));
        assert_eq!(record.result, None);
    }
    // Encoded NULL is a present one-octet value, not an empty destination list.
    let response = dispatch(
        &fixture.server,
        ConfirmedServiceChoice::WRITE_PROPERTY,
        wp(target, PropertyIdentifier::RECIPIENT_LIST, vec![0], None),
    )
    .await;
    let Apdu::Error(error) = response else {
        panic!("expected NULL type rejection: {response:?}")
    };
    assert_eq!(error.error_class, ErrorClass::PROPERTY);
    assert_eq!(error.error_code, ErrorCode::INVALID_DATA_TYPE);
    settle().await;
    let records = notifications(&fixture.transport.sent);
    assert_eq!(records.len(), 3);
    let record = &records[2].notifications[0];
    assert_eq!(record.target_value, Some(vec![0]));
    assert_eq!(record.current_value, Some(vec![]));
    assert_eq!(
        record.result,
        Some((ErrorClass::PROPERTY, ErrorCode::INVALID_DATA_TYPE))
    );
    assert_eq!(
        fixture
            .server
            .db
            .read()
            .await
            .get(&target)
            .unwrap()
            .read_property(PropertyIdentifier::RECIPIENT_LIST, None)
            .unwrap(),
        PropertyValue::ApplicationData(vec![])
    );
    fixture.server.stop().await.unwrap();
}

#[test]
fn audit_empty_values_small_known_values_preserve_zero_and_bound_32() {
    use super::audit_reporter::small_value;
    for empty in [
        PropertyValue::List(vec![]),
        PropertyValue::ApplicationData(vec![]),
    ] {
        assert_eq!(small_value(&empty), Some(vec![]));
    }
    for length in [32, 33] {
        for value in [
            PropertyValue::List(vec![PropertyValue::Null; length]),
            PropertyValue::ApplicationData(vec![0; length]),
        ] {
            assert_eq!(small_value(&value), (length <= 32).then(|| vec![0; length]));
        }
    }
    assert_eq!(small_value(&PropertyValue::Null), Some(vec![0]));
}
