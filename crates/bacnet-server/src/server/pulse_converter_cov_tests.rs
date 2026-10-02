//! Pulse Converter COV reporting over the wire (#1092).
//!
//! Table 13-1 has a Pulse Converter notification carry Update_Time after
//! Present_Value and Status_Flags. Update_Time is reported, not a trigger:
//! the notifications here come from Present_Value changes.
use super::cov_wire_test_support::*;
use super::*;
use bacnet_objects::accumulator::PulseConverterObject;
use bacnet_objects::traits::BACnetObject;
use bacnet_services::cov::{COVNotificationRequest, SubscribeCOVRequest};
use bacnet_services::write_property::WritePropertyRequest;
use bacnet_types::enums::ObjectType;
use std::sync::Mutex as StdMutex;

fn pc1() -> ObjectIdentifier {
    ObjectIdentifier::new(ObjectType::PULSE_CONVERTER, 1).unwrap()
}

/// `(property, value bytes)` of a Pulse Converter notification, in wire order.
fn values(notification: &COVNotificationRequest) -> Vec<(PropertyIdentifier, Vec<u8>)> {
    assert_eq!(notification.monitored_object_identifier, pc1());
    notification
        .list_of_values
        .iter()
        .map(|value| (value.property_identifier, value.value.clone()))
        .collect()
}

/// Update_Time as stamped at `at(7)`: Date 2026-09-29 (Tuesday), Time 15:00:07.00.
fn update_time() -> Vec<u8> {
    vec![0xA4, 126, 9, 29, 2, 0xB4, 15, 0, 7, 0]
}

#[tokio::test(start_paused = true)]
async fn pulse_converter_cov_notification_reports_update_time() {
    let mut h = Harness::start_with(ServerConfig::default(), |db| {
        let mut object = PulseConverterObject::new(1, "PC-1", 62).unwrap();
        // Accumulate under a clock reading 15:00:07 so Update_Time is set.
        let clock = SharedClock(Arc::new(StdMutex::new(at(7))));
        object.bind_clock_internal(Some(Arc::new(clock)));
        object.add_pulses(4).unwrap();
        db.add(Box::new(object)).unwrap();
    })
    .await;
    let mut body = BytesMut::new();
    SubscribeCOVRequest {
        subscriber_process_identifier: 1092,
        monitored_object_identifier: pc1(),
        issue_confirmed_notifications: Some(false),
        lifetime: Some(300),
    }
    .encode(&mut body)
    .unwrap();
    h.request(ConfirmedServiceChoice::SUBSCRIBE_COV, body).await;
    let flags = vec![0x82, 0x04, 0x00];
    assert_eq!(
        values(&h.cov_notification().await),
        vec![
            (PV, real(4.0)),
            (SF, flags.clone()),
            (PropertyIdentifier::UPDATE_TIME, update_time()),
        ]
    );

    // Doubling Scale_Factor moves Present_Value from 4 to 8; the report
    // carries the unchanged Update_Time with it.
    let mut encoded = BytesMut::new();
    bacnet_encoding::primitives::encode_property_value(&mut encoded, &PropertyValue::Real(2.0))
        .unwrap();
    let mut body = BytesMut::new();
    WritePropertyRequest {
        object_identifier: pc1(),
        property_identifier: PropertyIdentifier::SCALE_FACTOR,
        property_array_index: None,
        property_value: encoded.to_vec(),
        priority: None,
    }
    .encode(&mut body)
    .unwrap();
    h.request(ConfirmedServiceChoice::WRITE_PROPERTY, body)
        .await;
    assert_eq!(
        values(&h.cov_notification().await),
        vec![
            (PV, real(8.0)),
            (SF, flags),
            (PropertyIdentifier::UPDATE_TIME, update_time()),
        ]
    );
    h.no_notification().await;
    h.server.stop().await.unwrap();
}
