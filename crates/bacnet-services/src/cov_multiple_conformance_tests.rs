use super::*;
use bacnet_types::enums::ObjectType;

fn oid(object_type: ObjectType, instance: u32) -> ObjectIdentifier {
    ObjectIdentifier::new(object_type, instance).unwrap()
}

fn property_ref(property_identifier: PropertyIdentifier) -> COVReference {
    COVReference {
        monitored_property: PropertyReference {
            property_identifier,
            property_array_index: None,
        },
        cov_increment: None,
        timestamped: false,
    }
}

fn subscription_with(
    property_identifier: PropertyIdentifier,
) -> SubscribeCOVPropertyMultipleRequest {
    SubscribeCOVPropertyMultipleRequest {
        subscriber_process_identifier: 1,
        issue_confirmed_notifications: false,
        lifetime: Some(60),
        max_notification_delay: Some(5),
        list_of_cov_subscription_specifications: vec![COVSubscriptionSpecification {
            monitored_object_identifier: oid(ObjectType::ANALOG_INPUT, 1),
            list_of_cov_references: vec![property_ref(property_identifier)],
        }],
    }
}

fn notification_with(property_identifier: PropertyIdentifier) -> COVNotificationMultipleRequest {
    COVNotificationMultipleRequest {
        subscriber_process_identifier: 1,
        initiating_device_identifier: oid(ObjectType::DEVICE, 1),
        time_remaining: 1,
        timestamp: None,
        list_of_cov_notifications: vec![COVNotificationItem {
            monitored_object_identifier: oid(ObjectType::ANALOG_INPUT, 1),
            list_of_values: vec![COVNotificationValue {
                property_identifier,
                property_array_index: None,
                value: vec![0],
                time_of_change: None,
            }],
        }],
    }
}

fn raw_subscription(property_identifier: PropertyIdentifier) -> BytesMut {
    let mut encoded = BytesMut::new();
    primitives::encode_ctx_unsigned(&mut encoded, 0, 1);
    primitives::encode_ctx_boolean(&mut encoded, 1, false);
    primitives::encode_ctx_unsigned(&mut encoded, 2, 60);
    primitives::encode_ctx_unsigned(&mut encoded, 3, 5);
    tags::encode_opening_tag(&mut encoded, 4);
    primitives::encode_ctx_object_id(&mut encoded, 0, &oid(ObjectType::ANALOG_INPUT, 1));
    tags::encode_opening_tag(&mut encoded, 1);
    tags::encode_opening_tag(&mut encoded, 0);
    PropertyReference {
        property_identifier,
        property_array_index: None,
    }
    .encode(&mut encoded);
    tags::encode_closing_tag(&mut encoded, 0);
    primitives::encode_ctx_boolean(&mut encoded, 2, false);
    tags::encode_closing_tag(&mut encoded, 1);
    tags::encode_closing_tag(&mut encoded, 4);
    encoded
}

#[test]
fn subscribe_encodes_false_timestamped_and_rejects_missing_required_booleans() {
    let request = subscription_with(PropertyIdentifier::PRESENT_VALUE);
    let mut encoded = BytesMut::new();
    request.encode(&mut encoded);
    assert_eq!(
        encoded.as_ref(),
        &[
            0x09, 0x01, 0x19, 0x00, 0x29, 0x3c, 0x39, 0x05, 0x4e, 0x0c, 0x00, 0x00, 0x00, 0x01,
            0x1e, 0x0e, 0x09, 0x55, 0x0f, 0x29, 0x00, 0x1f, 0x4f,
        ]
    );

    let mut true_request = request.clone();
    true_request.issue_confirmed_notifications = true;
    true_request.list_of_cov_subscription_specifications[0].list_of_cov_references[0].timestamped =
        true;
    encoded.clear();
    true_request.encode(&mut encoded);
    assert_eq!(
        encoded.as_ref(),
        &[
            0x09, 0x01, 0x19, 0x01, 0x29, 0x3c, 0x39, 0x05, 0x4e, 0x0c, 0x00, 0x00, 0x00, 0x01,
            0x1e, 0x0e, 0x09, 0x55, 0x0f, 0x29, 0x01, 0x1f, 0x4f,
        ]
    );

    let mut missing_confirmed = BytesMut::new();
    primitives::encode_ctx_unsigned(&mut missing_confirmed, 0, 1);
    tags::encode_opening_tag(&mut missing_confirmed, 4);
    tags::encode_closing_tag(&mut missing_confirmed, 4);
    assert!(SubscribeCOVPropertyMultipleRequest::decode(&missing_confirmed).is_err());

    let mut missing_timestamped = raw_subscription(PropertyIdentifier::PRESENT_VALUE).to_vec();
    let timestamped = missing_timestamped
        .windows(2)
        .rposition(|window| window == [0x29, 0x00])
        .unwrap();
    missing_timestamped.drain(timestamped..timestamped + 2);
    assert!(SubscribeCOVPropertyMultipleRequest::decode(&missing_timestamped).is_err());
}

#[test]
fn subscribe_rejects_empty_reference_lists_and_special_property_identifiers() {
    let empty = SubscribeCOVPropertyMultipleRequest {
        subscriber_process_identifier: 1,
        issue_confirmed_notifications: false,
        lifetime: None,
        max_notification_delay: None,
        list_of_cov_subscription_specifications: vec![COVSubscriptionSpecification {
            monitored_object_identifier: oid(ObjectType::ANALOG_INPUT, 1),
            list_of_cov_references: Vec::new(),
        }],
    };
    let mut encoded = BytesMut::new();
    assert!(empty.try_encode(&mut encoded).is_err());

    for property_identifier in [
        PropertyIdentifier::ALL,
        PropertyIdentifier::OPTIONAL,
        PropertyIdentifier::REQUIRED,
    ] {
        let request = subscription_with(property_identifier);
        let mut encoded = BytesMut::new();
        assert!(request.try_encode(&mut encoded).is_err());
        assert!(
            SubscribeCOVPropertyMultipleRequest::decode(&raw_subscription(property_identifier))
                .is_err()
        );
    }

    let proprietary = PropertyIdentifier::from_raw(512);
    let request = subscription_with(proprietary);
    encoded.clear();
    request.try_encode(&mut encoded).unwrap();
    assert_eq!(
        SubscribeCOVPropertyMultipleRequest::decode(&encoded)
            .unwrap()
            .list_of_cov_subscription_specifications[0]
            .list_of_cov_references[0]
            .monitored_property
            .property_identifier,
        proprietary
    );
}

#[test]
fn notification_decodes_standard_datetime_and_primitive_time_of_change() {
    let date = bacnet_types::primitives::Date {
        year: 126,
        month: 8,
        day: 20,
        day_of_week: 4,
    };
    let time = bacnet_types::primitives::Time {
        hour: 12,
        minute: 34,
        second: 56,
        hundredths: 78,
    };
    let mut encoded = BytesMut::new();
    primitives::encode_ctx_unsigned(&mut encoded, 0, 1);
    primitives::encode_ctx_object_id(&mut encoded, 1, &oid(ObjectType::DEVICE, 1));
    primitives::encode_ctx_unsigned(&mut encoded, 2, 1);
    tags::encode_opening_tag(&mut encoded, 3);
    primitives::encode_app_date(&mut encoded, &date);
    primitives::encode_app_time(&mut encoded, &time);
    tags::encode_closing_tag(&mut encoded, 3);
    tags::encode_opening_tag(&mut encoded, 4);
    primitives::encode_ctx_object_id(&mut encoded, 0, &oid(ObjectType::ANALOG_INPUT, 1));
    tags::encode_opening_tag(&mut encoded, 1);
    primitives::encode_ctx_unsigned(
        &mut encoded,
        0,
        PropertyIdentifier::PRESENT_VALUE.to_raw() as u64,
    );
    tags::encode_opening_tag(&mut encoded, 2);
    encoded.extend_from_slice(&[0]);
    tags::encode_closing_tag(&mut encoded, 2);
    tags::encode_tag(&mut encoded, 3, tags::TagClass::Context, 4);
    encoded.extend_from_slice(&time.encode());
    tags::encode_closing_tag(&mut encoded, 1);
    tags::encode_closing_tag(&mut encoded, 4);

    let decoded = COVNotificationMultipleRequest::decode(&encoded).unwrap();
    assert_eq!(decoded.timestamp, Some((date, time)));
    assert_eq!(
        decoded.list_of_cov_notifications[0].list_of_values[0].time_of_change,
        Some(time)
    );
    let mut reencoded = BytesMut::new();
    decoded.encode(&mut reencoded).unwrap();
    assert_eq!(reencoded, encoded);
}

#[test]
fn timestamp_and_time_of_change_presence_must_agree() {
    let date = bacnet_types::primitives::Date {
        year: 126,
        month: 8,
        day: 20,
        day_of_week: 4,
    };
    let time = bacnet_types::primitives::Time {
        hour: 12,
        minute: 34,
        second: 56,
        hundredths: 78,
    };

    let mut request = notification_with(PropertyIdentifier::PRESENT_VALUE);
    let mut output = BytesMut::from(&b"prefix"[..]);
    request.timestamp = Some((date, time));
    assert!(request.encode(&mut output).is_err());
    assert_eq!(output.as_ref(), b"prefix");

    request.timestamp = None;
    request.list_of_cov_notifications[0].list_of_values[0].time_of_change = Some(time);
    assert!(request.encode(&mut output).is_err());
    assert_eq!(output.as_ref(), b"prefix");

    request.timestamp = Some((date, time));
    request.encode(&mut output).unwrap();
    assert!(output.len() > b"prefix".len());
}

#[test]
fn encoder_validation_is_atomic_and_caps_total_nested_items() {
    let mut invalid_subscription = subscription_with(PropertyIdentifier::ALL);
    let mut output = BytesMut::from(&b"prefix"[..]);
    assert!(invalid_subscription.try_encode(&mut output).is_err());
    assert_eq!(output.as_ref(), b"prefix");

    invalid_subscription.list_of_cov_subscription_specifications[0].list_of_cov_references =
        vec![property_ref(PropertyIdentifier::PRESENT_VALUE); MAX_DECODED_ITEMS + 1];
    assert!(invalid_subscription.try_encode(&mut output).is_err());
    assert_eq!(output.as_ref(), b"prefix");

    let mut exact = subscription_with(PropertyIdentifier::PRESENT_VALUE);
    exact.list_of_cov_subscription_specifications[0].list_of_cov_references =
        vec![property_ref(PropertyIdentifier::PRESENT_VALUE); MAX_DECODED_ITEMS];
    let mut encoded = BytesMut::new();
    exact.try_encode(&mut encoded).unwrap();
    assert_eq!(
        SubscribeCOVPropertyMultipleRequest::decode(&encoded)
            .unwrap()
            .list_of_cov_subscription_specifications[0]
            .list_of_cov_references
            .len(),
        MAX_DECODED_ITEMS
    );

    let value = notification_with(PropertyIdentifier::PRESENT_VALUE).list_of_cov_notifications[0]
        .list_of_values[0]
        .clone();
    let mut notification = notification_with(PropertyIdentifier::PRESENT_VALUE);
    notification.list_of_cov_notifications[0].list_of_values =
        vec![value.clone(); MAX_DECODED_ITEMS];
    encoded.clear();
    notification.encode(&mut encoded).unwrap();
    assert_eq!(
        COVNotificationMultipleRequest::decode(&encoded)
            .unwrap()
            .list_of_cov_notifications[0]
            .list_of_values
            .len(),
        MAX_DECODED_ITEMS
    );
    notification.list_of_cov_notifications[0]
        .list_of_values
        .push(value);
    output.truncate(b"prefix".len());
    assert!(notification.encode(&mut output).is_err());
    assert_eq!(output.as_ref(), b"prefix");
}

#[test]
fn notification_rejects_legacy_timestamp_and_time_shapes() {
    let mut primitive_timestamp = BytesMut::new();
    primitives::encode_ctx_unsigned(&mut primitive_timestamp, 0, 1);
    primitives::encode_ctx_object_id(&mut primitive_timestamp, 1, &oid(ObjectType::DEVICE, 1));
    primitives::encode_ctx_unsigned(&mut primitive_timestamp, 2, 1);
    primitives::encode_ctx_unsigned(&mut primitive_timestamp, 3, 1);
    tags::encode_opening_tag(&mut primitive_timestamp, 4);
    tags::encode_closing_tag(&mut primitive_timestamp, 4);
    assert!(COVNotificationMultipleRequest::decode(&primitive_timestamp).is_err());

    let mut malformed_value = notification_with(PropertyIdentifier::PRESENT_VALUE);
    malformed_value.list_of_cov_notifications[0].list_of_values[0].value = vec![0x2e];
    let mut output = BytesMut::from(&b"prefix"[..]);
    assert!(malformed_value.encode(&mut output).is_err());
    assert_eq!(output.as_ref(), b"prefix");
}

#[test]
fn notification_rejects_empty_lists_and_special_property_identifiers() {
    let empty_outer = COVNotificationMultipleRequest {
        subscriber_process_identifier: 1,
        initiating_device_identifier: oid(ObjectType::DEVICE, 1),
        time_remaining: 1,
        timestamp: None,
        list_of_cov_notifications: Vec::new(),
    };
    let mut encoded = BytesMut::new();
    primitives::encode_ctx_unsigned(&mut encoded, 0, 1);
    primitives::encode_ctx_object_id(&mut encoded, 1, &oid(ObjectType::DEVICE, 1));
    primitives::encode_ctx_unsigned(&mut encoded, 2, 1);
    tags::encode_opening_tag(&mut encoded, 4);
    tags::encode_closing_tag(&mut encoded, 4);
    assert!(COVNotificationMultipleRequest::decode(&encoded).is_err());

    let mut empty_values = notification_with(PropertyIdentifier::PRESENT_VALUE);
    empty_values.list_of_cov_notifications[0]
        .list_of_values
        .clear();
    encoded.clear();
    assert!(empty_values.encode(&mut encoded).is_err());

    for property_identifier in [
        PropertyIdentifier::ALL,
        PropertyIdentifier::OPTIONAL,
        PropertyIdentifier::REQUIRED,
    ] {
        let request = notification_with(property_identifier);
        encoded.clear();
        assert!(request.encode(&mut encoded).is_err());

        let valid = notification_with(PropertyIdentifier::PRESENT_VALUE);
        valid.encode(&mut encoded).unwrap();
        let property_tag = encoded
            .windows(2)
            .rposition(|window| window == [0x09, 0x55])
            .unwrap();
        encoded[property_tag + 1] = property_identifier.to_raw() as u8;
        assert!(COVNotificationMultipleRequest::decode(&encoded).is_err());
    }
}
