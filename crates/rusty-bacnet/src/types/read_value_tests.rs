use super::*;
use bacnet_types::primitives::{Date, ObjectIdentifier, Time};

const AI: ObjectType = ObjectType::ANALOG_INPUT;
const PV: PropertyIdentifier = PropertyIdentifier::PRESENT_VALUE;

fn oid(instance: u32) -> PropertyValue {
    PropertyValue::ObjectIdentifier(ObjectIdentifier::new(AI, instance).unwrap())
}

fn object_list(instances: &[u32]) -> Vec<u8> {
    instances
        .iter()
        .flat_map(|&instance| {
            let mut element = vec![0xC4];
            element.extend_from_slice(&((AI.to_raw() << 22) | instance).to_be_bytes());
            element
        })
        .collect()
}

#[test]
fn one_application_element_is_the_bare_value() {
    assert_eq!(
        decode_read_value(AI, PV, None, &[0x44, 0x41, 0xAC, 0x00, 0x00]).unwrap(),
        PropertyValue::Real(21.5)
    );
}

#[test]
fn several_application_elements_are_a_list_in_wire_order() {
    // A BACnetDateTime on a scalar property: a Date, then a Time.
    let date_time = [0xA4, 126, 10, 3, 6, 0xB4, 12, 30, 0, 0];
    assert_eq!(
        decode_read_value(
            ObjectType::LOAD_CONTROL,
            PropertyIdentifier::START_TIME,
            None,
            &date_time
        )
        .unwrap(),
        PropertyValue::List(vec![
            PropertyValue::Date(Date {
                year: 126,
                month: 10,
                day: 3,
                day_of_week: 6
            }),
            PropertyValue::Time(Time {
                hour: 12,
                minute: 30,
                second: 0,
                hundredths: 0
            }),
        ])
    );
}

#[test]
fn a_whole_array_or_list_is_a_list_at_every_length() {
    let device = ObjectType::DEVICE;
    let list = PropertyIdentifier::OBJECT_LIST;
    assert_eq!(
        decode_read_value(device, list, None, &object_list(&[1, 2, 3])).unwrap(),
        PropertyValue::List(vec![oid(1), oid(2), oid(3)])
    );
    assert_eq!(
        decode_read_value(device, list, None, &object_list(&[7])).unwrap(),
        PropertyValue::List(vec![oid(7)])
    );
    assert_eq!(
        decode_read_value(device, list, None, &[]).unwrap(),
        PropertyValue::List(vec![])
    );
    // A BACnetLIST of application values: a multi-state object's Alarm_Values.
    assert_eq!(
        decode_read_value(
            ObjectType::MULTI_STATE_INPUT,
            PropertyIdentifier::ALARM_VALUES,
            None,
            &[0x21, 0x02]
        )
        .unwrap(),
        PropertyValue::List(vec![PropertyValue::Unsigned(2)])
    );
    // One element of an array is that element, and index 0 is the count.
    assert_eq!(
        decode_read_value(device, list, Some(1), &object_list(&[7])).unwrap(),
        oid(7)
    );
    assert_eq!(
        decode_read_value(device, list, Some(0), &[0x21, 0x01]).unwrap(),
        PropertyValue::Unsigned(1)
    );
    // Present_Value is a list only on a Group.
    assert_eq!(
        decode_read_value(AI, PV, None, &[0x44, 0x41, 0xAC, 0x00, 0x00]).unwrap(),
        PropertyValue::Real(21.5)
    );
}

#[test]
fn context_tagged_content_keeps_every_octet() {
    // Two BACnetPortPermission elements: port [0], enable [1].
    let port_filter = [0x09, 0x01, 0x19, 0x01, 0x09, 0x02, 0x19, 0x00];
    assert_eq!(
        decode_read_value(
            ObjectType::NOTIFICATION_FORWARDER,
            PropertyIdentifier::PORT_FILTER,
            None,
            &port_filter
        )
        .unwrap(),
        PropertyValue::ApplicationData(port_filter.to_vec())
    );
    // A BACnetDestination: application fields around a context-tagged
    // recipient, so the first element alone would drop most of it.
    let mut destination = vec![0x82, 0x01, 0xFE, 0xB4, 0, 0, 0, 0, 0xB4, 23, 59, 59, 99];
    destination.extend_from_slice(&[0x0C, 0x02, 0x00, 0x00, 0x09, 0x21, 0x01, 0x10]);
    destination.extend_from_slice(&[0x82, 0x05, 0xE0]);
    assert_eq!(
        decode_read_value(
            ObjectType::NOTIFICATION_CLASS,
            PropertyIdentifier::RECIPIENT_LIST,
            None,
            &destination
        )
        .unwrap(),
        PropertyValue::ApplicationData(destination.clone())
    );
    // A Group's result: object [0], then results [1] opening and closing.
    let group = [0x0C, 0, 0, 0, 1, 0x1E, 0x29, 0x55, 0x4E, 0x10, 0x4F, 0x1F];
    assert_eq!(
        decode_read_value(ObjectType::GROUP, PV, None, &group).unwrap(),
        PropertyValue::ApplicationData(group.to_vec())
    );
}

#[test]
fn malformed_octets_are_an_error_wherever_they_sit() {
    // A REAL cut short.
    assert!(decode_read_value(AI, PV, None, &[0x44, 0x41]).is_err());
    // A valid first element followed by a truncated one.
    assert!(decode_read_value(AI, PV, None, &[0x21, 0x01, 0x44]).is_err());
    // An opening context tag with no closing tag, after an application value.
    assert!(decode_read_value(AI, PV, None, &[0x21, 0x01, 0x1E, 0x21, 0x01]).is_err());
}
