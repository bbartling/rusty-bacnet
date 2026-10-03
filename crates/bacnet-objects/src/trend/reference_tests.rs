//! Log_DeviceObjectProperty on the trend objects themselves (#1234): the
//! served encoding, the purge a change triggers, and the local setters'
//! refusals. The wire tests live in bacnet-server's `log_reference_writes`.

use super::*;
use crate::clock::{ClockFrame, ClockReader};
use bacnet_types::primitives::{Date, Time};

const P: PropertyIdentifier = PropertyIdentifier::LOG_DEVICE_OBJECT_PROPERTY;

/// [0] analog-input 1, [1] present-value.
const AI1_PV: [u8; 7] = [0x0C, 0x00, 0x00, 0x00, 0x01, 0x19, 0x55];

struct FixedClock;

impl ClockReader for FixedClock {
    fn read_clock(&self) -> Option<ClockFrame> {
        Some(ClockFrame {
            local_date: Date {
                year: 126,
                month: 10,
                day: 3,
                day_of_week: 6,
            },
            local_time: Time {
                hour: 9,
                minute: 0,
                second: 0,
                hundredths: 0,
            },
            utc_offset: 0,
            daylight_savings_status: false,
        })
    }
}

fn oid(object_type: ObjectType, instance: u32) -> ObjectIdentifier {
    ObjectIdentifier::new(object_type, instance).unwrap()
}

fn reference(device: Option<ObjectIdentifier>) -> BACnetDeviceObjectPropertyReference {
    BACnetDeviceObjectPropertyReference {
        object_identifier: oid(ObjectType::ANALOG_INPUT, 1),
        property_identifier: PropertyIdentifier::PRESENT_VALUE.to_raw(),
        property_array_index: None,
        device_identifier: device,
    }
}

fn assert_error(result: Result<(), Error>, class: ErrorClass, code: ErrorCode) {
    assert!(
        matches!(result, Err(Error::Protocol { class: c, code: e })
            if c == class.to_raw() as u32 && e == code.to_raw() as u32),
        "expected {class:?} / {code:?}, got {result:?}"
    );
}

fn record_count(object: &dyn BACnetObject) -> usize {
    object.log_buffer_internal().unwrap().record_count()
}

#[test]
fn trend_log_write_purges_on_change_and_needs_a_clock_to() {
    let mut tl = TrendLogObject::new(1, "TL-1", 4).unwrap();
    let framed = PropertyValue::ApplicationData(AI1_PV.to_vec());
    // Without a clock the purge has no timestamp, so the change is refused.
    assert_error(
        tl.write_property(P, None, framed.clone(), None),
        ErrorClass::DEVICE,
        ErrorCode::OPERATIONAL_PROBLEM,
    );
    assert_eq!(tl.read_property(P, None).unwrap(), PropertyValue::Null);
    // Writing the value already held is no change, so needs no clock.
    tl.write_property(P, None, PropertyValue::Null, None)
        .unwrap();

    tl.bind_clock_internal(Some(Arc::new(FixedClock)));
    tl.write_property(P, None, framed.clone(), None).unwrap();
    assert_eq!(tl.read_property(P, None).unwrap(), framed);
    assert_eq!(record_count(&tl), 1);
    // The read-back shape, chunked as a read of it decodes, also lands.
    tl.write_property(
        P,
        None,
        PropertyValue::List(vec![PropertyValue::ApplicationData(AI1_PV.to_vec())]),
        None,
    )
    .unwrap();
    assert_eq!(record_count(&tl), 1);
}

#[test]
fn trend_log_setter_refuses_a_device_member_that_is_no_device() {
    let mut tl = TrendLogObject::new(1, "TL-1", 4).unwrap();
    // The application may point the log at another device.
    tl.set_log_device_object_property(Some(reference(Some(oid(ObjectType::DEVICE, 9)))))
        .unwrap();
    let served = tl.read_property(P, None).unwrap();
    assert_error(
        tl.set_log_device_object_property(Some(reference(Some(oid(ObjectType::ANALOG_INPUT, 9))))),
        ErrorClass::PROPERTY,
        ErrorCode::VALUE_OUT_OF_RANGE,
    );
    assert_eq!(tl.read_property(P, None).unwrap(), served);
    // A client may not: the poller reads only its own database.
    tl.bind_clock_internal(Some(Arc::new(FixedClock)));
    assert_error(
        tl.write_property(
            P,
            None,
            PropertyValue::ApplicationData([&AI1_PV[..], &[0x3C, 0x02, 0x00, 0x00, 0x0A]].concat()),
            None,
        ),
        ErrorClass::PROPERTY,
        ErrorCode::OPTIONAL_FUNCTIONALITY_NOT_SUPPORTED,
    );
    assert_eq!(tl.read_property(P, None).unwrap(), served);
}

#[test]
fn trend_log_multiple_serves_one_encoding_per_element() {
    let mut tlm = TrendLogMultipleObject::new(1, "TLM-1", 4).unwrap();
    assert!(tlm.is_array_property(P));
    assert!(!TrendLogObject::new(1, "TL-1", 4)
        .unwrap()
        .is_array_property(P));
    tlm.add_property_reference(reference(None)).unwrap();
    tlm.add_property_reference(reference(Some(oid(ObjectType::DEVICE, 9))))
        .unwrap();
    let remote = [&AI1_PV[..], &[0x3C, 0x02, 0x00, 0x00, 0x09]].concat();
    assert_eq!(
        tlm.read_property(P, None).unwrap(),
        PropertyValue::List(vec![
            PropertyValue::ApplicationData(AI1_PV.to_vec()),
            PropertyValue::ApplicationData(remote.clone()),
        ])
    );
    assert_eq!(
        tlm.read_property(P, Some(0)).unwrap(),
        PropertyValue::Unsigned(2)
    );
    assert_eq!(
        tlm.read_property(P, Some(2)).unwrap(),
        PropertyValue::ApplicationData(remote)
    );
    assert!(tlm.read_property(P, Some(3)).is_err());
}

#[test]
fn trend_log_multiple_indexed_write_checks_only_the_element_written() {
    let mut tlm = TrendLogMultipleObject::new(1, "TLM-1", 4).unwrap();
    tlm.bind_clock_internal(Some(Arc::new(FixedClock)));
    // Element 2, set locally, names another device.
    tlm.add_property_reference(reference(None)).unwrap();
    tlm.add_property_reference(reference(Some(oid(ObjectType::DEVICE, 9))))
        .unwrap();
    let slot16 = [0x0C, 0x00, 0x00, 0x00, 0x01, 0x19, 0x57, 0x29, 0x10];
    tlm.write_property(
        P,
        Some(1),
        PropertyValue::ApplicationData(slot16.to_vec()),
        None,
    )
    .unwrap();
    assert_eq!(
        tlm.read_property(P, Some(1)).unwrap(),
        PropertyValue::ApplicationData(slot16.to_vec())
    );
    assert_eq!(record_count(&tlm), 1);
}

#[test]
fn trend_log_multiple_setter_bounds_the_array() {
    let mut tlm = TrendLogMultipleObject::new(1, "TLM-1", 4).unwrap();
    for _ in 0..MAX_LOG_DEVICE_OBJECT_PROPERTIES {
        tlm.add_property_reference(reference(None)).unwrap();
    }
    assert_error(
        tlm.add_property_reference(reference(None)),
        ErrorClass::RESOURCES,
        ErrorCode::NO_SPACE_TO_WRITE_PROPERTY,
    );
    assert_error(
        TrendLogMultipleObject::new(2, "TLM-2", 4)
            .unwrap()
            .add_property_reference(reference(Some(oid(ObjectType::ANALOG_INPUT, 9)))),
        ErrorClass::PROPERTY,
        ErrorCode::VALUE_OUT_OF_RANGE,
    );
    assert_eq!(
        tlm.read_property(P, Some(0)).unwrap(),
        PropertyValue::Unsigned(MAX_LOG_DEVICE_OBJECT_PROPERTIES as u64)
    );
}
