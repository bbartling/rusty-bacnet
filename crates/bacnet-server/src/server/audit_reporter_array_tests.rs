//! Audit coordinate evidence uses a writable State_Text array.
use super::*;

#[tokio::test]
async fn audit_reporter_known_source_array_coordinate_and_large_value_policy() {
    let mut fixture = server(reporter()).await;
    fixture
        .server
        .device_bindings
        .write()
        .await
        .insert_configured(
            DeviceBinding::local(oid(ObjectType::DEVICE, 30), SOURCE).unwrap(),
            |_| false,
        )
        .unwrap();
    // Audit an actually writable array; Priority_Array is read-only (§19.2.1).
    fixture
        .server
        .database()
        .write()
        .await
        .add(Box::new(
            bacnet_objects::multistate::MultiStateValueObject::new(1, "audit-array", 2).unwrap(),
        ))
        .unwrap();
    let mut old = BytesMut::new();
    encode_property_value(&mut old, &PropertyValue::CharacterString("State 2".into())).unwrap();
    let mut value = BytesMut::new();
    encode_property_value(
        &mut value,
        &PropertyValue::CharacterString("new label".into()),
    )
    .unwrap();
    let mut request = BytesMut::new();
    WritePropertyRequest {
        object_identifier: oid(ObjectType::MULTI_STATE_VALUE, 1),
        property_identifier: PropertyIdentifier::STATE_TEXT,
        property_array_index: Some(2),
        property_value: value.to_vec(),
        priority: None,
    }
    .encode(&mut request)
    .unwrap();
    assert!(matches!(
        dispatch(
            &fixture.server,
            ConfirmedServiceChoice::WRITE_PROPERTY,
            request.freeze()
        )
        .await,
        Apdu::SimpleAck(_)
    ));
    settle().await;
    let records = notifications(&fixture.transport.sent);
    assert_eq!(records.len(), 1);
    let record = &records[0].notifications[0];
    assert_eq!(
        record.source_device,
        BACnetRecipient::Device(oid(ObjectType::DEVICE, 30))
    );
    assert_eq!(
        record
            .target_property
            .as_ref()
            .unwrap()
            .property_array_index,
        Some(2)
    );
    assert_eq!(record.current_value, Some(old.to_vec()));
    assert_eq!(record.target_priority, None);
    for size in [29, 30, 31, 1000] {
        let mut encoded = BytesMut::new();
        encode_property_value(
            &mut encoded,
            &PropertyValue::CharacterString("x".repeat(size)),
        )
        .unwrap();
        let included = (encoded.len() <= 32).then(|| encoded.to_vec());
        dispatch(
            &fixture.server,
            ConfirmedServiceChoice::WRITE_PROPERTY,
            wp(
                oid(ObjectType::BINARY_VALUE, 1),
                PropertyIdentifier::DESCRIPTION,
                encoded.to_vec(),
                None,
            ),
        )
        .await;
        settle().await;
        assert_eq!(
            notifications(&fixture.transport.sent)
                .last()
                .unwrap()
                .notifications[0]
                .target_value,
            included
        );
    }
    fixture.server.stop().await.unwrap();
}
