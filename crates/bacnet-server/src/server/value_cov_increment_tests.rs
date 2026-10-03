//! COV_Increment on Integer, Positive Integer and Large Analog Value, end to
//! end (#1111).
//!
//! Table 13-1 puts these three types with the analog objects: a SubscribeCOV
//! notification goes out when Present_Value moves by COV_Increment from the
//! value last reported. Each test subscribes, then commands Present_Value by
//! less than the increment (nothing goes out), by exactly the increment (a
//! notification), by less again, and by more (a notification).
use super::cov_wire_test_support::*;
use super::*;
use bacnet_objects::traits::BACnetObject;
use bacnet_objects::value_types::{
    IntegerValueObject, LargeAnalogValueObject, PositiveIntegerValueObject,
};
use bacnet_services::cov::{COVNotificationRequest, SubscribeCOVRequest};
use bacnet_services::write_property::WritePropertyRequest;

/// Status_Flags with no flag set.
const NO_FLAGS: [u8; 3] = [0x82, 0x04, 0x00];

fn encoded(value: &PropertyValue) -> Vec<u8> {
    let mut buf = BytesMut::new();
    bacnet_encoding::primitives::encode_property_value(&mut buf, value).unwrap();
    buf.to_vec()
}

/// Subscribe to `object`, take the first notification, then command each of
/// `steps` at priority 8. A step whose flag is set must send a notification
/// carrying that Present_Value; any other must send none.
async fn run(
    object: Box<dyn BACnetObject>,
    initial: PropertyValue,
    steps: &[(PropertyValue, bool)],
) {
    let oid = object.object_identifier();
    let mut h = Harness::start_with(ServerConfig::default(), |db| {
        db.add(object).unwrap();
    })
    .await;
    let mut body = BytesMut::new();
    SubscribeCOVRequest {
        subscriber_process_identifier: 1111,
        monitored_object_identifier: oid,
        issue_confirmed_notifications: Some(false),
        lifetime: Some(300),
    }
    .encode(&mut body)
    .unwrap();
    h.request(ConfirmedServiceChoice::SUBSCRIBE_COV, body).await;
    let expect = |notification: COVNotificationRequest, value: &PropertyValue| {
        assert_eq!(notification.monitored_object_identifier, oid);
        let values: Vec<_> = notification
            .list_of_values
            .iter()
            .map(|v| (v.property_identifier, v.value.clone()))
            .collect();
        assert_eq!(
            values,
            vec![(PV, encoded(value)), (SF, NO_FLAGS.to_vec())],
            "{oid:?}"
        );
    };
    expect(h.cov_notification().await, &initial);

    for (value, notifies) in steps {
        let mut body = BytesMut::new();
        WritePropertyRequest {
            object_identifier: oid,
            property_identifier: PV,
            property_array_index: None,
            property_value: encoded(value),
            priority: Some(8),
        }
        .encode(&mut body)
        .unwrap();
        h.request(ConfirmedServiceChoice::WRITE_PROPERTY, body)
            .await;
        assert_eq!(response(&h).await, Ok(()), "{oid:?} {value:?}");
        if *notifies {
            expect(h.cov_notification().await, value);
        } else {
            h.no_notification().await;
        }
    }
    h.no_notification().await;
    h.server.stop().await.unwrap();
}

#[tokio::test(start_paused = true)]
async fn integer_value_cov_notifies_at_and_above_its_increment_only() {
    let mut iv = IntegerValueObject::new(1, "IV-1").unwrap();
    iv.set_cov_increment(5).unwrap();
    use PropertyValue::Signed;
    run(
        Box::new(iv),
        Signed(0),
        &[
            (Signed(4), false),
            (Signed(5), true),
            (Signed(9), false),
            (Signed(-2), true),
        ],
    )
    .await;
}

#[tokio::test(start_paused = true)]
async fn positive_integer_value_cov_notifies_at_and_above_its_increment_only() {
    let mut piv = PositiveIntegerValueObject::new(1, "PIV-1").unwrap();
    piv.set_cov_increment(5).unwrap();
    use PropertyValue::Unsigned;
    run(
        Box::new(piv),
        Unsigned(0),
        &[
            (Unsigned(4), false),
            (Unsigned(5), true),
            (Unsigned(9), false),
            (Unsigned(12), true),
        ],
    )
    .await;
}

#[tokio::test(start_paused = true)]
async fn large_analog_value_cov_notifies_at_and_above_its_double_increment_only() {
    // 0.1 has no exact REAL; compared as the Double it was written as, a move
    // of exactly 0.1 reaches it.
    let mut lav = LargeAnalogValueObject::new(1, "LAV-1").unwrap();
    lav.set_cov_increment(0.1).unwrap();
    use PropertyValue::Double;
    run(
        Box::new(lav),
        Double(0.0),
        &[
            (Double(0.05), false),
            (Double(0.1), true),
            (Double(0.15), false),
            (Double(0.35), true),
        ],
    )
    .await;
}

#[tokio::test(start_paused = true)]
async fn numeric_value_cov_increment_written_over_the_wire_takes_effect() {
    // The default increment is 0, so every move notifies until a client
    // writes a larger one.
    let mut h = Harness::start_with(ServerConfig::default(), |db| {
        db.add(Box::new(IntegerValueObject::new(2, "IV-2").unwrap()))
            .unwrap();
    })
    .await;
    let oid = ObjectIdentifier::new(bacnet_types::enums::ObjectType::INTEGER_VALUE, 2).unwrap();
    let write = |property: PropertyIdentifier, value: PropertyValue, priority: Option<u8>| {
        let mut body = BytesMut::new();
        WritePropertyRequest {
            object_identifier: oid,
            property_identifier: property,
            property_array_index: None,
            property_value: encoded(&value),
            priority,
        }
        .encode(&mut body)
        .unwrap();
        body
    };
    let mut body = BytesMut::new();
    SubscribeCOVRequest {
        subscriber_process_identifier: 1111,
        monitored_object_identifier: oid,
        issue_confirmed_notifications: Some(false),
        lifetime: Some(300),
    }
    .encode(&mut body)
    .unwrap();
    h.request(ConfirmedServiceChoice::SUBSCRIBE_COV, body).await;
    h.cov_notification().await;
    h.request(
        ConfirmedServiceChoice::WRITE_PROPERTY,
        write(PV, PropertyValue::Signed(1), Some(8)),
    )
    .await;
    assert_eq!(response(&h).await, Ok(()));
    h.cov_notification().await;

    h.request(
        ConfirmedServiceChoice::WRITE_PROPERTY,
        write(
            PropertyIdentifier::COV_INCREMENT,
            PropertyValue::Unsigned(10),
            None,
        ),
    )
    .await;
    assert_eq!(response(&h).await, Ok(()));
    h.request(
        ConfirmedServiceChoice::WRITE_PROPERTY,
        write(PV, PropertyValue::Signed(10), Some(8)),
    )
    .await;
    assert_eq!(response(&h).await, Ok(()));
    h.no_notification().await;
    h.request(
        ConfirmedServiceChoice::WRITE_PROPERTY,
        write(PV, PropertyValue::Signed(11), Some(8)),
    )
    .await;
    assert_eq!(response(&h).await, Ok(()));
    let notification = h.cov_notification().await;
    assert_eq!(
        notification.list_of_values[0].value,
        encoded(&PropertyValue::Signed(11))
    );
    h.no_notification().await;
    h.server.stop().await.unwrap();
}
