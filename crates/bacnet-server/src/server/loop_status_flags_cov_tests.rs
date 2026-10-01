//! A Loop's computed Status_Flags reaches COV subscribers (#978).
//!
//! Loop used to report a Status_Flags fixed at construction, so a subscriber
//! never heard of a fault or of Out_Of_Service. Each WriteProperty below
//! changes only Status_Flags, and must produce one notification carrying the
//! new flags.
use super::cov_wire_test_support::*;
use super::*;
use bacnet_objects::loop_obj::LoopObject;
use bacnet_services::cov::{COVNotificationRequest, SubscribeCOVRequest};
use bacnet_services::write_property::WritePropertyRequest;
use bacnet_types::enums::{ObjectType, Reliability};

const FAULT: u8 = 0x40;
const OUT_OF_SERVICE: u8 = 0x10;

fn loop1() -> ObjectIdentifier {
    ObjectIdentifier::new(ObjectType::LOOP, 1).unwrap()
}

/// The Status_Flags bits of a notification's application-tagged BIT STRING.
fn cov_flags(notification: &COVNotificationRequest) -> u8 {
    assert_eq!(notification.monitored_object_identifier, loop1());
    let value = &notification
        .list_of_values
        .iter()
        .find(|value| value.property_identifier == SF)
        .expect("Status_Flags reported with Present_Value")
        .value;
    assert_eq!(&value[..2], &[0x82, 0x04], "four-bit Status_Flags");
    value[2]
}

async fn subscribe_loop(h: &mut Harness) {
    let mut body = BytesMut::new();
    SubscribeCOVRequest {
        subscriber_process_identifier: 978,
        monitored_object_identifier: loop1(),
        issue_confirmed_notifications: Some(false),
        lifetime: Some(300),
    }
    .encode(&mut body)
    .unwrap();
    h.request(ConfirmedServiceChoice::SUBSCRIBE_COV, body).await;
}

async fn write_loop(h: &mut Harness, property: PropertyIdentifier, value: PropertyValue) {
    let mut encoded = BytesMut::new();
    bacnet_encoding::primitives::encode_property_value(&mut encoded, &value).unwrap();
    let mut body = BytesMut::new();
    WritePropertyRequest {
        object_identifier: loop1(),
        property_identifier: property,
        property_array_index: None,
        property_value: encoded.to_vec(),
        priority: None,
    }
    .encode(&mut body)
    .unwrap();
    h.request(ConfirmedServiceChoice::WRITE_PROPERTY, body)
        .await;
}

#[tokio::test]
async fn loop_fault_and_out_of_service_notify_cov_subscribers() {
    let mut h = Harness::start_with(ServerConfig::default(), |db| {
        db.add(Box::new(LoopObject::new(1, "LOOP-1", 62).unwrap()))
            .unwrap();
    })
    .await;
    subscribe_loop(&mut h).await;
    assert_eq!(cov_flags(&h.cov_notification().await), 0, "initial report");

    write_loop(
        &mut h,
        PropertyIdentifier::OUT_OF_SERVICE,
        PropertyValue::Boolean(true),
    )
    .await;
    assert_eq!(cov_flags(&h.cov_notification().await), OUT_OF_SERVICE);

    write_loop(
        &mut h,
        PropertyIdentifier::RELIABILITY,
        PropertyValue::Enumerated(Reliability::OPEN_LOOP.to_raw()),
    )
    .await;
    assert_eq!(
        cov_flags(&h.cov_notification().await),
        FAULT | OUT_OF_SERVICE,
        "a simulated fault must reach the subscriber"
    );

    // Returning to service restores the evaluated NO_FAULT_DETECTED.
    write_loop(
        &mut h,
        PropertyIdentifier::OUT_OF_SERVICE,
        PropertyValue::Boolean(false),
    )
    .await;
    assert_eq!(cov_flags(&h.cov_notification().await), 0);

    // A write that leaves Present_Value and Status_Flags alone reports nothing.
    write_loop(
        &mut h,
        PropertyIdentifier::SETPOINT,
        PropertyValue::Real(21.0),
    )
    .await;
    h.no_notification().await;
    h.server.stop().await.unwrap();
}
