//! Event notification requests round-trip, and malformed ones fail to decode.

use super::*;

#[test]
fn event_notification_round_trip() {
    let device_oid = ObjectIdentifier::new(ObjectType::DEVICE, 1).unwrap();
    let ai_oid = ObjectIdentifier::new(ObjectType::ANALOG_INPUT, 3).unwrap();

    let req = EventNotificationRequest {
        process_identifier: 1,
        initiating_device_identifier: device_oid,
        event_object_identifier: ai_oid,
        timestamp: BACnetTimeStamp::SequenceNumber(7),
        notification_class: 5,
        priority: 100,
        event_type: EventType::OUT_OF_RANGE,
        message_text: None,
        notify_type: NotifyType::ALARM,
        ack_required: true,
        from_state: EventState::NORMAL,
        to_state: EventState::HIGH_LIMIT,
        event_values: None,
    };
    let mut buf = BytesMut::new();
    encode_event_notification(&req, &mut buf).unwrap();

    let decoded = decode_event_notification(&buf).unwrap();
    assert_eq!(decoded.process_identifier, 1);
    assert_eq!(decoded.initiating_device_identifier, device_oid);
    assert_eq!(decoded.event_object_identifier, ai_oid);
    assert_eq!(decoded.timestamp, BACnetTimeStamp::SequenceNumber(7));
    assert_eq!(decoded.notification_class, 5);
    assert_eq!(decoded.priority, 100);
    assert_eq!(decoded.event_type, EventType::OUT_OF_RANGE);
    assert_eq!(decoded.notify_type, NotifyType::ALARM);
    assert!(decoded.ack_required);
    assert_eq!(decoded.from_state, EventState::NORMAL);
    assert_eq!(decoded.to_state, EventState::HIGH_LIMIT);
    assert!(decoded.event_values.is_none());
}

#[test]
fn event_notification_datetime_timestamp_round_trip() {
    use bacnet_types::primitives::{Date, Time};

    let device_oid = ObjectIdentifier::new(ObjectType::DEVICE, 1).unwrap();
    let ai_oid = ObjectIdentifier::new(ObjectType::ANALOG_INPUT, 3).unwrap();

    let ts = BACnetTimeStamp::DateTime {
        date: Date {
            year: 126,
            month: 2,
            day: 28,
            day_of_week: 6,
        },
        time: Time {
            hour: 14,
            minute: 30,
            second: 0,
            hundredths: 0,
        },
    };

    let req = EventNotificationRequest {
        process_identifier: 1,
        initiating_device_identifier: device_oid,
        event_object_identifier: ai_oid,
        timestamp: ts.clone(),
        notification_class: 5,
        priority: 100,
        event_type: EventType::OUT_OF_RANGE,
        message_text: None,
        notify_type: NotifyType::ALARM,
        ack_required: true,
        from_state: EventState::NORMAL,
        to_state: EventState::HIGH_LIMIT,
        event_values: None,
    };
    let mut buf = BytesMut::new();
    encode_event_notification(&req, &mut buf).unwrap();

    let decoded = decode_event_notification(&buf).unwrap();
    assert_eq!(decoded.timestamp, ts);
}

#[test]
fn event_notification_time_timestamp_round_trip() {
    use bacnet_types::primitives::Time;

    let device_oid = ObjectIdentifier::new(ObjectType::DEVICE, 1).unwrap();
    let ai_oid = ObjectIdentifier::new(ObjectType::ANALOG_INPUT, 3).unwrap();

    let ts = BACnetTimeStamp::Time(Time {
        hour: 10,
        minute: 15,
        second: 30,
        hundredths: 50,
    });

    let req = EventNotificationRequest {
        process_identifier: 1,
        initiating_device_identifier: device_oid,
        event_object_identifier: ai_oid,
        timestamp: ts.clone(),
        notification_class: 5,
        priority: 100,
        event_type: EventType::OUT_OF_RANGE,
        message_text: None,
        notify_type: NotifyType::ALARM,
        ack_required: true,
        from_state: EventState::NORMAL,
        to_state: EventState::HIGH_LIMIT,
        event_values: None,
    };
    let mut buf = BytesMut::new();
    encode_event_notification(&req, &mut buf).unwrap();

    let decoded = decode_event_notification(&buf).unwrap();
    assert_eq!(decoded.timestamp, ts);
}

#[test]
fn test_decode_event_notification_empty_input() {
    assert!(decode_event_notification(&[]).is_err());
}

#[test]
fn test_decode_event_notification_truncated_1_byte() {
    let device_oid = ObjectIdentifier::new(ObjectType::DEVICE, 1).unwrap();
    let ai_oid = ObjectIdentifier::new(ObjectType::ANALOG_INPUT, 3).unwrap();
    let req = EventNotificationRequest {
        process_identifier: 1,
        initiating_device_identifier: device_oid,
        event_object_identifier: ai_oid,
        timestamp: BACnetTimeStamp::SequenceNumber(7),
        notification_class: 5,
        priority: 100,
        event_type: EventType::OUT_OF_RANGE,
        message_text: None,
        notify_type: NotifyType::ALARM,
        ack_required: true,
        from_state: EventState::NORMAL,
        to_state: EventState::HIGH_LIMIT,
        event_values: None,
    };
    let mut buf = BytesMut::new();
    encode_event_notification(&req, &mut buf).unwrap();
    assert!(decode_event_notification(&buf[..1]).is_err());
}

#[test]
fn test_decode_event_notification_truncated_3_bytes() {
    let device_oid = ObjectIdentifier::new(ObjectType::DEVICE, 1).unwrap();
    let ai_oid = ObjectIdentifier::new(ObjectType::ANALOG_INPUT, 3).unwrap();
    let req = EventNotificationRequest {
        process_identifier: 1,
        initiating_device_identifier: device_oid,
        event_object_identifier: ai_oid,
        timestamp: BACnetTimeStamp::SequenceNumber(7),
        notification_class: 5,
        priority: 100,
        event_type: EventType::OUT_OF_RANGE,
        message_text: None,
        notify_type: NotifyType::ALARM,
        ack_required: true,
        from_state: EventState::NORMAL,
        to_state: EventState::HIGH_LIMIT,
        event_values: None,
    };
    let mut buf = BytesMut::new();
    encode_event_notification(&req, &mut buf).unwrap();
    assert!(decode_event_notification(&buf[..3]).is_err());
}

#[test]
fn test_decode_event_notification_truncated_half() {
    let device_oid = ObjectIdentifier::new(ObjectType::DEVICE, 1).unwrap();
    let ai_oid = ObjectIdentifier::new(ObjectType::ANALOG_INPUT, 3).unwrap();
    let req = EventNotificationRequest {
        process_identifier: 1,
        initiating_device_identifier: device_oid,
        event_object_identifier: ai_oid,
        timestamp: BACnetTimeStamp::SequenceNumber(7),
        notification_class: 5,
        priority: 100,
        event_type: EventType::OUT_OF_RANGE,
        message_text: None,
        notify_type: NotifyType::ALARM,
        ack_required: true,
        from_state: EventState::NORMAL,
        to_state: EventState::HIGH_LIMIT,
        event_values: None,
    };
    let mut buf = BytesMut::new();
    encode_event_notification(&req, &mut buf).unwrap();
    let half = buf.len() / 2;
    assert!(decode_event_notification(&buf[..half]).is_err());
}

#[test]
fn test_decode_event_notification_invalid_tag() {
    assert!(decode_event_notification(&[0xFF, 0xFF, 0xFF]).is_err());
}
