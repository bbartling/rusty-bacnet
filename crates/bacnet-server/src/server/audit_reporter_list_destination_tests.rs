//! Recipient_List edits reach the audit log only once both the request's
//! destinations and the stored list decode (#152, #1026, #1027).

use super::*;

#[tokio::test]
async fn audit_reporter_list_framed_destinations_decode_before_observation() {
    use bacnet_objects::notification_class::NotificationClass;
    use bacnet_types::{
        bitstring::{DaysOfWeek, EventTransitionBits},
        constructed::BACnetDestination,
        primitives::Time,
    };
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
    let mut delta = BytesMut::new();
    bacnet_encoding::constructed::encode_destination_list(
        &mut delta,
        std::slice::from_ref(&destination),
    );
    assert!(delta.len() <= 32);
    for service in SERVICES {
        let mut fixture = list_server(vec![1]).await;
        let mut object = NotificationClass::new(1, "destinations").unwrap();
        object.add_destination(destination.clone()).unwrap();
        fixture
            .server
            .db
            .write()
            .await
            .add(Box::new(object))
            .unwrap();
        // A valid frame followed by a valid TLV that is NOT a destination
        // distinguishes service decoding from the late framed decoder.
        for object in [target, oid(ObjectType::NOTIFICATION_CLASS, 999)] {
            let mut malformed = delta.to_vec();
            malformed.extend_from_slice(&[0x21, 2]);
            let request = list_request(object, PropertyIdentifier::RECIPIENT_LIST, None, malformed);
            assert!(ListElementRequest::decode(&request).is_ok());
            let response = dispatch(&fixture.server, service, request).await;
            // The second element is the one that is not a destination.
            let expected = if object == target {
                (ErrorClass::PROPERTY, ErrorCode::INVALID_DATA_TYPE, 2)
            } else {
                (ErrorClass::OBJECT, ErrorCode::UNKNOWN_OBJECT, 0)
            };
            assert_eq!(change_list_error(response, service), expected);
        }
        settle().await;
        assert!(notifications(&fixture.transport.sent).is_empty());
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
            PropertyValue::ApplicationData(delta.to_vec())
        );
        let response = dispatch(
            &fixture.server,
            service,
            list_request(
                target,
                PropertyIdentifier::RECIPIENT_LIST,
                None,
                delta.to_vec(),
            ),
        )
        .await;
        assert!(matches!(response, Apdu::SimpleAck(_)));
        settle().await;
        let records = notifications(&fixture.transport.sent);
        assert_eq!(records.len(), 1);
        let record = &records[0].notifications[0];
        assert_eq!(record.target_value, Some(delta.to_vec()));
        assert_eq!(record.current_value, Some(delta.to_vec()));
        assert_eq!(record.result, None);
        // The destination is present: adding it again leaves the list as it is.
        let after = if service == SERVICES[0] {
            delta.to_vec()
        } else {
            vec![]
        };
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
            PropertyValue::ApplicationData(after)
        );
        // Valid framed content with an unknown object is an execution failure.
        let response = dispatch(
            &fixture.server,
            service,
            list_request(
                oid(ObjectType::NOTIFICATION_CLASS, 999),
                PropertyIdentifier::RECIPIENT_LIST,
                None,
                delta.to_vec(),
            ),
        )
        .await;
        assert_eq!(
            error_fields(response, service),
            (ErrorClass::OBJECT, ErrorCode::UNKNOWN_OBJECT)
        );
        settle().await;
        let records = notifications(&fixture.transport.sent);
        assert_eq!(records.len(), 2);
        assert_eq!(records[1].notifications[0].current_value, None);
        assert_eq!(
            records[1].notifications[0].result,
            Some((ErrorClass::OBJECT, ErrorCode::UNKNOWN_OBJECT))
        );
        fixture.server.stop().await.unwrap();
    }
}
