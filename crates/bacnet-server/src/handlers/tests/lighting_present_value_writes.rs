//! Lighting Output Present_Value levels over WriteProperty and ReadProperty
//! (#1385, Clause 12.54.4): a level above 0.0 and below 1.0 is stored as 1.0
//! in the priority slot and read back as 1.0 from Present_Value,
//! Priority_Array and Tracking_Value. 0.0 and 1.0 to 100.0 are stored as
//! written; a level outside 0.0 to 100.0 is PROPERTY / VALUE_OUT_OF_RANGE.
//!
//! A REAL reads as `44` and four octets: 1.0 is `3F800000`.

use super::lighting_required_rows::{assert_refused, db_with, write_wire};
use super::*;
use bacnet_objects::lighting::LightingOutputObject;

const PV: PropertyIdentifier = PropertyIdentifier::PRESENT_VALUE;
const ONE: [u8; 5] = [0x44, 0x3F, 0x80, 0x00, 0x00];
const OFF: [u8; 5] = [0x44, 0x00, 0x00, 0x00, 0x00];

fn read_at(
    db: &ObjectDatabase,
    oid: ObjectIdentifier,
    property: PropertyIdentifier,
    index: Option<u32>,
) -> Vec<u8> {
    let mut request = BytesMut::new();
    ReadPropertyRequest {
        object_identifier: oid,
        property_identifier: property,
        property_array_index: index,
    }
    .encode(&mut request);
    let mut response = BytesMut::new();
    handle_read_property(db, &request, &mut response).unwrap();
    ReadPropertyACK::decode(&response).unwrap().property_value
}

/// Present_Value, Priority_Array[8] and Tracking_Value as served.
fn levels_at_8(db: &ObjectDatabase, oid: ObjectIdentifier) -> [Vec<u8>; 3] {
    [
        read_at(db, oid, PV, None),
        read_at(db, oid, PropertyIdentifier::PRIORITY_ARRAY, Some(8)),
        read_at(db, oid, PropertyIdentifier::TRACKING_VALUE, None),
    ]
}

fn served(level: f32) -> Vec<u8> {
    let mut bytes = vec![0x44];
    bytes.extend_from_slice(&level.to_be_bytes());
    bytes
}

#[test]
fn lighting_output_present_value_below_one_percent_reads_one_percent_over_the_wire() {
    let (mut db, oid) = db_with(Box::new(LightingOutputObject::new(1, "LO-1").unwrap()));
    for level in [f32::from_bits(1), 0.001, 0.5, 1.0f32.next_down()] {
        write_wire(&mut db, oid, PV, PropertyValue::Real(level), Some(8)).unwrap();
        assert_eq!(levels_at_8(&db, oid), [ONE; 3].map(Vec::from), "{level:e}");
        write_wire(&mut db, oid, PV, PropertyValue::Null, Some(8)).unwrap();
        assert_eq!(read_at(&db, oid, PV, None), OFF);
    }
    for level in [0.0, 1.0, 1.0f32.next_up(), 100.0] {
        write_wire(&mut db, oid, PV, PropertyValue::Real(level), Some(8)).unwrap();
        let expected = served(level);
        assert_eq!(
            levels_at_8(&db, oid),
            [(); 3].map(|_| expected.clone()),
            "{level:e}"
        );
    }
}

#[test]
fn lighting_output_present_value_outside_the_range_is_refused_over_the_wire() {
    let (mut db, oid) = db_with(Box::new(LightingOutputObject::new(1, "LO-1").unwrap()));
    write_wire(&mut db, oid, PV, PropertyValue::Real(0.5), Some(8)).unwrap();
    for level in [-f32::from_bits(1), -1.5, 100.0f32.next_up(), f32::NAN] {
        assert_refused(
            write_wire(&mut db, oid, PV, PropertyValue::Real(level), Some(8)),
            ErrorCode::VALUE_OUT_OF_RANGE,
        );
        assert_eq!(levels_at_8(&db, oid), [ONE; 3].map(Vec::from), "{level:e}");
    }
    // Relinquishing the slot still falls back to Relinquish_Default.
    write_wire(&mut db, oid, PV, PropertyValue::Null, Some(8)).unwrap();
    assert_eq!(
        read_at(&db, oid, PropertyIdentifier::PRIORITY_ARRAY, Some(8)),
        [0x00]
    );
    assert_eq!(read_at(&db, oid, PV, None), OFF);
    assert_eq!(
        read_at(&db, oid, PropertyIdentifier::TRACKING_VALUE, None),
        OFF
    );
}
