//! A member of an event notification cut short, inside the event values'
//! frames included, is a short buffer (#1333).

use super::*;

fn date_time() -> (Date, Time) {
    (
        Date {
            year: 126,
            month: 10,
            day: 4,
            day_of_week: 7,
        },
        Time {
            hour: 10,
            minute: 30,
            second: 0,
            hundredths: 0,
        },
    )
}

fn request(event_values: Option<NotificationParameters>) -> EventNotificationRequest {
    let (date, time) = date_time();
    EventNotificationRequest {
        process_identifier: 1,
        initiating_device_identifier: ObjectIdentifier::new(ObjectType::DEVICE, 1).unwrap(),
        event_object_identifier: ObjectIdentifier::new(ObjectType::ANALOG_INPUT, 3).unwrap(),
        timestamp: BACnetTimeStamp::DateTime { date, time },
        notification_class: 300,
        priority: 1,
        event_type: EventType::CHANGE_OF_STATE,
        message_text: Some("note".into()),
        notify_type: NotifyType::ALARM,
        ack_required: true,
        from_state: EventState::NORMAL,
        to_state: EventState::FAULT,
        event_values,
    }
}

#[test]
fn members_cut_short_are_a_short_buffer() {
    let reference = BACnetDeviceObjectPropertyReference::new_local(
        ObjectIdentifier::new(ObjectType::TREND_LOG, 1).unwrap(),
        131,
    );
    let unsigned = vec![0x22, 0x01, 0x2C];
    let event_values = [
        None,
        Some(NotificationParameters::OutOfRange {
            exceeding_value: 85.5,
            status_flags: StatusFlags::IN_ALARM,
            deadband: 1.0,
            exceeded_limit: 80.0,
        }),
        Some(NotificationParameters::ChangeOfState {
            new_state: BACnetPropertyStates::UnsignedValue(300),
            status_flags: StatusFlags::IN_ALARM,
        }),
        Some(NotificationParameters::ChangeOfValue {
            new_value: ChangeOfValueChoice::ChangedValue(12.5),
            status_flags: StatusFlags::IN_ALARM,
        }),
        Some(NotificationParameters::CommandFailure {
            command_value: unsigned.clone(),
            status_flags: StatusFlags::IN_ALARM,
            feedback_value: unsigned.clone(),
        }),
        Some(NotificationParameters::ChangeOfReliability {
            reliability: Reliability::UNRELIABLE_OTHER,
            status_flags: StatusFlags::IN_ALARM,
            property_values: Vec::new(),
        }),
        Some(NotificationParameters::BufferReady {
            buffer_property: reference,
            previous_notification: 1,
            current_notification: 300,
        }),
        Some(NotificationParameters::Extended {
            vendor_id: 42,
            extended_event_type: 7,
            parameters: unsigned,
        }),
        Some(NotificationParameters::ChangeOfTimer {
            new_state: TimerState::RUNNING,
            status_flags: StatusFlags::IN_ALARM,
            update_time: date_time(),
            last_state_change: Some(TimerTransition::RUNNING_TO_IDLE),
            initial_timeout: Some(300),
            expiration_time: Some(date_time()),
        }),
    ];
    for event_values in event_values {
        let mut octets = BytesMut::new();
        encode_event_notification(&request(event_values.clone()), &mut octets).unwrap();
        let framed = assert_members_cut_short("EventNotification", &octets, |data| {
            decode_event_notification(data)
        });
        assert!(framed > 0, "{event_values:?}");
    }
}
