use super::*;
use bacnet_client::client::EventNotificationDelivery;
use bacnet_encoding::constructed::{
    encode_destination_list, encode_event_notification_subscription_list,
};
use bacnet_objects::notification_forwarder::NotificationForwarderObject;
use bacnet_services::alarm_event::EventNotificationRequest;
use bacnet_types::bitstring::{DaysOfWeek, EventTransitionBits};
use bacnet_types::constructed::{
    BACnetAddress, BACnetDestination, BACnetEventNotificationSubscription, BACnetRecipient,
    PropertyReference, ReadAccessSpecification,
};
use bacnet_types::enums::{EventState, EventType, NotifyType};
use bacnet_types::primitives::{BACnetTimeStamp, Time};

fn at(mac: &[u8]) -> BACnetRecipient {
    BACnetRecipient::Address(BACnetAddress {
        network_number: 0,
        mac_address: MacAddr::from_slice(mac),
    })
}

fn alarm(process_identifier: u32) -> EventNotificationRequest {
    EventNotificationRequest {
        process_identifier,
        initiating_device_identifier: ObjectIdentifier::new(ObjectType::DEVICE, 900).unwrap(),
        event_object_identifier: ObjectIdentifier::new(ObjectType::ANALOG_INPUT, 12).unwrap(),
        timestamp: BACnetTimeStamp::SequenceNumber(31),
        notification_class: 3,
        priority: 90,
        event_type: EventType::CHANGE_OF_STATE,
        message_text: Some("door open".into()),
        notify_type: NotifyType::EVENT,
        ack_required: false,
        from_state: EventState::NORMAL,
        to_state: EventState::OFFNORMAL,
        event_values: None,
    }
}

/// The Notification Forwarder end to end over loopback UDP (#1225): a client
/// configures the forwarder's filter, subscribes another client and adds it
/// to Recipient_List, then sends a ConfirmedEventNotification. The sender is
/// acknowledged, the subscribed client gets one unconfirmed copy and one
/// confirmed copy, each with its own process identifier, and the rows read
/// back through ReadPropertyMultiple.
#[tokio::test]
async fn forwarder_relays_a_notification_between_clients_over_the_wire() {
    let mut server = make_server().await;
    let mut sender = make_client().await;
    let mut listener = make_client().await;
    let server_mac = server.local_mac().to_vec();
    let listener_mac = listener.local_mac().to_vec();
    let mut received = listener.event_notifications();
    let forwarder = ObjectIdentifier::new(ObjectType::NOTIFICATION_FORWARDER, 1).unwrap();
    server
        .database()
        .write()
        .await
        .add(Box::new(
            NotificationForwarderObject::new(1, "Forwarder").unwrap(),
        ))
        .unwrap();

    // Process_Identifier_Filter 5 (application Unsigned).
    sender
        .write_property(
            &server_mac,
            forwarder,
            PropertyIdentifier::PROCESS_IDENTIFIER_FILTER,
            None,
            vec![0x21, 0x05],
            None,
        )
        .await
        .unwrap();
    let mut subscriptions = BytesMut::new();
    encode_event_notification_subscription_list(
        &mut subscriptions,
        &[BACnetEventNotificationSubscription {
            recipient: at(&listener_mac),
            process_identifier: 77,
            issue_confirmed_notifications: false,
            time_remaining: 10,
        }],
    );
    sender
        .write_property(
            &server_mac,
            forwarder,
            PropertyIdentifier::SUBSCRIBED_RECIPIENTS,
            None,
            subscriptions.to_vec(),
            None,
        )
        .await
        .unwrap();
    let mut destinations = BytesMut::new();
    encode_destination_list(
        &mut destinations,
        &[BACnetDestination {
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
                second: 59,
                hundredths: 99,
            },
            recipient: at(&listener_mac),
            process_identifier: 78,
            issue_confirmed_notifications: true,
            transitions: EventTransitionBits::all(),
        }],
    );
    sender
        .add_list_element(
            &server_mac,
            forwarder,
            PropertyIdentifier::RECIPIENT_LIST,
            None,
            destinations.to_vec(),
        )
        .await
        .unwrap();

    let mut request = BytesMut::new();
    alarm(5).encode(&mut request).unwrap();
    let ack = sender
        .confirmed_request(
            &server_mac,
            ConfirmedServiceChoice::CONFIRMED_EVENT_NOTIFICATION,
            &request,
        )
        .await
        .unwrap();
    assert!(ack.is_empty(), "a SimpleACK carries no body");

    let mut copies = Vec::new();
    for _ in 0..2 {
        let copy = tokio::time::timeout(Duration::from_secs(5), received.recv())
            .await
            .expect("forwarded copy arrives")
            .unwrap();
        assert_eq!(copy.source_mac.as_slice(), server_mac.as_slice());
        copies.push((
            copy.notification.process_identifier,
            copy.delivery,
            copy.notification.initiating_device_identifier,
            copy.notification.event_object_identifier,
            copy.notification.message_text,
            copy.notification.to_state,
        ));
    }
    copies.sort_by_key(|copy| copy.0);
    let sent = alarm(5);
    let expected = |process, delivery| {
        (
            process,
            delivery,
            sent.initiating_device_identifier,
            sent.event_object_identifier,
            sent.message_text.clone(),
            sent.to_state,
        )
    };
    assert_eq!(
        copies,
        [
            expected(77, EventNotificationDelivery::Unconfirmed),
            expected(78, EventNotificationDelivery::Confirmed),
        ]
    );

    let rows = sender
        .read_property_multiple(
            &server_mac,
            vec![ReadAccessSpecification {
                object_identifier: forwarder,
                list_of_property_references: vec![PropertyReference {
                    property_identifier: PropertyIdentifier::ALL,
                    property_array_index: None,
                }],
            }],
        )
        .await
        .unwrap();
    let row = |property| {
        rows.list_of_read_access_results[0]
            .list_of_results
            .iter()
            .find(|result| result.property_identifier == property)
            .and_then(|result| result.property_value.clone())
    };
    assert_eq!(row(PropertyIdentifier::OBJECT_TYPE), Some(vec![0x91, 51]));
    assert_eq!(
        row(PropertyIdentifier::PROCESS_IDENTIFIER_FILTER),
        Some(vec![0x21, 0x05])
    );
    assert_eq!(
        row(PropertyIdentifier::LOCAL_FORWARDING_ONLY),
        Some(vec![0x10])
    );
    assert_eq!(row(PropertyIdentifier::OUT_OF_SERVICE), Some(vec![0x10]));
    assert_eq!(
        row(PropertyIdentifier::RECIPIENT_LIST),
        Some(destinations.to_vec())
    );
    assert_eq!(
        row(PropertyIdentifier::SUBSCRIBED_RECIPIENTS),
        Some(subscriptions.to_vec())
    );
    assert!(row(PropertyIdentifier::STATUS_FLAGS).is_some());
    assert!(row(PropertyIdentifier::RELIABILITY).is_some());

    server.stop().await.unwrap();
    sender.stop().await.unwrap();
    listener.stop().await.unwrap();
}
