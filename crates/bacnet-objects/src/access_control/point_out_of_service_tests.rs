//! The access events an Access Point records on its Out_Of_Service edges
//! (Clauses 12.31.8 and 12.31.27 to 12.31.29, #1248).

use std::sync::Arc;

use bacnet_types::enums::{ErrorCode, PropertyIdentifier as P};

use super::credential_data_input_out_of_service_tests::{
    assert_property_error, sequence, stamp, stamped, FixedClock,
};
use super::*;

/// A point whose last event was GRANTED in transaction 7 at 09:30, on a
/// Device clock reading 11:30.
fn point() -> AccessPointObject {
    let mut point = AccessPointObject::new(1, "AP-1").unwrap();
    point.set_access_event(AccessEvent::GRANTED, 7, stamp(9));
    point.bind_clock_internal(Some(Arc::new(FixedClock(11))));
    point
}

fn write_out_of_service(point: &mut AccessPointObject, value: PropertyValue) -> Result<(), Error> {
    point.write_property(P::OUT_OF_SERVICE, None, value, None)
}

/// Access_Event, Access_Event_Tag, Access_Event_Time and Status_Flags as
/// served.
fn served(point: &AccessPointObject) -> [PropertyValue; 4] {
    [
        P::ACCESS_EVENT,
        P::ACCESS_EVENT_TAG,
        P::ACCESS_EVENT_TIME,
        P::STATUS_FLAGS,
    ]
    .map(|property| point.read_property(property, None).unwrap())
}

fn event(
    event: AccessEvent,
    tag: u64,
    time: PropertyValue,
    out_of_service: bool,
) -> [PropertyValue; 4] {
    let mut flags = StatusFlags::empty();
    flags.set(StatusFlags::OUT_OF_SERVICE, out_of_service);
    [
        PropertyValue::Enumerated(event.to_raw()),
        PropertyValue::Unsigned(tag),
        time,
        PropertyValue::BitString {
            unused_bits: 4,
            data: vec![flags.bits() << 4],
        },
    ]
}

/// The GRANTED event the point starts from.
fn granted(out_of_service: bool) -> [PropertyValue; 4] {
    event(AccessEvent::GRANTED, 7, stamped(9), out_of_service)
}

#[test]
fn access_point_entering_out_of_service_records_out_of_service() {
    let mut point = point();
    assert_eq!(served(&point), granted(false));
    write_out_of_service(&mut point, PropertyValue::Boolean(true)).unwrap();
    // A new transaction, stamped from the Device clock.
    assert_eq!(
        served(&point),
        event(AccessEvent::OUT_OF_SERVICE, 8, stamped(11), true)
    );
}

#[test]
fn access_point_return_to_service_records_out_of_service_relinquished() {
    let mut point = point();
    write_out_of_service(&mut point, PropertyValue::Boolean(true)).unwrap();
    point.bind_clock_internal(Some(Arc::new(FixedClock(12))));
    write_out_of_service(&mut point, PropertyValue::Boolean(false)).unwrap();
    assert_eq!(
        served(&point),
        event(
            AccessEvent::OUT_OF_SERVICE_RELINQUISHED,
            9,
            stamped(12),
            false
        )
    );

    // A second period out of service records a pair of its own.
    point.bind_clock_internal(Some(Arc::new(FixedClock(13))));
    write_out_of_service(&mut point, PropertyValue::Boolean(true)).unwrap();
    assert_eq!(
        served(&point),
        event(AccessEvent::OUT_OF_SERVICE, 10, stamped(13), true)
    );
}

#[test]
fn access_point_writes_that_keep_out_of_service_record_nothing() {
    let mut point = point();
    // FALSE while in service, NULL and a refused datatype are no edges.
    write_out_of_service(&mut point, PropertyValue::Boolean(false)).unwrap();
    write_out_of_service(&mut point, PropertyValue::Null).unwrap();
    assert_property_error(
        write_out_of_service(&mut point, PropertyValue::Unsigned(1)),
        ErrorCode::INVALID_DATA_TYPE,
    );
    assert_eq!(served(&point), granted(false));

    // TRUE again while out of service records nothing more either.
    write_out_of_service(&mut point, PropertyValue::Boolean(true)).unwrap();
    let entered = served(&point);
    point.bind_clock_internal(Some(Arc::new(FixedClock(12))));
    write_out_of_service(&mut point, PropertyValue::Boolean(true)).unwrap();
    write_out_of_service(&mut point, PropertyValue::Null).unwrap();
    assert_eq!(served(&point), entered);
}

#[test]
fn access_point_out_of_service_event_without_a_clock_stamps_the_tag_as_a_sequence_number() {
    let mut point = point();
    point.bind_clock_internal(None);
    write_out_of_service(&mut point, PropertyValue::Boolean(true)).unwrap();
    assert_eq!(
        served(&point),
        event(AccessEvent::OUT_OF_SERVICE, 8, sequence(8), true)
    );
    write_out_of_service(&mut point, PropertyValue::Boolean(false)).unwrap();
    assert_eq!(
        served(&point),
        event(
            AccessEvent::OUT_OF_SERVICE_RELINQUISHED,
            9,
            sequence(9),
            false
        )
    );
}

#[test]
fn access_point_sequence_number_folds_a_tag_past_its_range() {
    let mut point = point();
    point.bind_clock_internal(None);
    // A tag up to 65535 is its own sequence number; 65536 folds back to 1.
    point.set_access_event(AccessEvent::GRANTED, 65_534, stamp(9));
    write_out_of_service(&mut point, PropertyValue::Boolean(true)).unwrap();
    assert_eq!(
        served(&point),
        event(AccessEvent::OUT_OF_SERVICE, 65_535, sequence(65_535), true)
    );
    write_out_of_service(&mut point, PropertyValue::Boolean(false)).unwrap();
    assert_eq!(
        served(&point),
        event(
            AccessEvent::OUT_OF_SERVICE_RELINQUISHED,
            65_536,
            sequence(1),
            false
        )
    );
    // The tag's own wrap to 0 gives 1 too, never the 0 of no update yet.
    point.set_access_event(AccessEvent::GRANTED, u64::MAX, stamp(9));
    write_out_of_service(&mut point, PropertyValue::Boolean(true)).unwrap();
    assert_eq!(
        served(&point),
        event(AccessEvent::OUT_OF_SERVICE, 0, sequence(1), true)
    );
}

#[test]
fn access_point_out_of_service_event_tag_wraps_at_the_top_of_its_range() {
    let mut point = point();
    point.set_access_event(AccessEvent::GRANTED, u64::MAX, stamp(9));
    write_out_of_service(&mut point, PropertyValue::Boolean(true)).unwrap();
    assert_eq!(
        served(&point),
        event(AccessEvent::OUT_OF_SERVICE, 0, stamped(11), true)
    );
}
