//! State_Text written whole over WriteProperty and WritePropertyMultiple
//! sets a multi-state object's Number_Of_States (#1443), and a shrink that
//! would strand a state the object holds is VALUE_OUT_OF_RANGE.

use super::*;
use bacnet_objects::multistate::{
    MultiStateInputObject, MultiStateOutputObject, MultiStateValueObject,
};
use bacnet_services::common::BACnetPropertyValue;
use bacnet_services::wpm::WriteAccessSpecification;
use PropertyIdentifier as P;

fn octets(value: &PropertyValue) -> Vec<u8> {
    let mut bytes = BytesMut::new();
    encode_property_value(&mut bytes, value).unwrap();
    bytes.to_vec()
}

fn labels(count: usize) -> PropertyValue {
    PropertyValue::List(
        (1..=count)
            .map(|state| PropertyValue::CharacterString(format!("Mode {state}")))
            .collect(),
    )
}

fn read(db: &ObjectDatabase, oid: ObjectIdentifier, property: P) -> PropertyValue {
    db.get(&oid).unwrap().read_property(property, None).unwrap()
}

fn wp(db: &mut ObjectDatabase, oid: ObjectIdentifier, value: &PropertyValue) -> Result<(), Error> {
    let mut request = BytesMut::new();
    WritePropertyRequest {
        object_identifier: oid,
        property_identifier: P::STATE_TEXT,
        property_array_index: None,
        property_value: octets(value),
        priority: None,
    }
    .encode(&mut request)
    .unwrap();
    handle_write_property(db, &request).map(|_| ())
}

fn wpm(
    db: &mut ObjectDatabase,
    oid: ObjectIdentifier,
    values: &[PropertyValue],
) -> Result<(), Error> {
    let mut request = BytesMut::new();
    WritePropertyMultipleRequest {
        list_of_write_access_specs: vec![WriteAccessSpecification {
            object_identifier: oid,
            list_of_properties: values
                .iter()
                .map(|value| BACnetPropertyValue {
                    property_identifier: P::STATE_TEXT,
                    property_array_index: None,
                    value: octets(value),
                    priority: None,
                })
                .collect(),
        }],
    }
    .encode(&mut request)
    .unwrap();
    handle_write_property_multiple(db, &request).map(|_| ())
}

fn out_of_range(result: Result<(), Error>) -> bool {
    matches!(result, Err(Error::Protocol { class, code })
        if class == ErrorClass::PROPERTY.to_raw() as u32
            && code == ErrorCode::VALUE_OUT_OF_RANGE.to_raw() as u32)
}

fn db() -> (ObjectDatabase, [ObjectIdentifier; 3]) {
    let mut db = ObjectDatabase::new();
    let mut input = MultiStateInputObject::new(1, "MSI-1", 4).unwrap();
    input.set_present_value(3);
    let mut output = MultiStateOutputObject::new(1, "MSO-1", 4).unwrap();
    output.set_relinquish_default(3).unwrap();
    let mut value = MultiStateValueObject::new(1, "MSV-1", 4).unwrap();
    value.set_alarm_values(vec![3]);
    let oids = [
        input.object_identifier(),
        output.object_identifier(),
        value.object_identifier(),
    ];
    db.add(Box::new(input)).unwrap();
    db.add(Box::new(output)).unwrap();
    db.add(Box::new(value)).unwrap();
    (db, oids)
}

#[test]
fn a_whole_state_text_write_resizes_the_count() {
    let (mut db, oids) = db();
    for oid in oids {
        wp(&mut db, oid, &labels(6)).unwrap();
        assert_eq!(
            read(&db, oid, P::NUMBER_OF_STATES),
            PropertyValue::Unsigned(6)
        );
        assert_eq!(read(&db, oid, P::STATE_TEXT), labels(6));
        // Each holds state 3, so three states are the fewest it takes.
        assert!(out_of_range(wp(&mut db, oid, &labels(2))), "{oid:?}");
        assert_eq!(read(&db, oid, P::STATE_TEXT), labels(6), "{oid:?}");
        wp(&mut db, oid, &labels(3)).unwrap();
        assert_eq!(
            read(&db, oid, P::NUMBER_OF_STATES),
            PropertyValue::Unsigned(3)
        );
    }
}

#[test]
fn write_property_multiple_resizes_in_order_and_stops_at_the_refusal() {
    let (mut db, oids) = db();
    for oid in oids {
        // The last of several whole writes sets the count.
        wpm(&mut db, oid, &[labels(5), labels(4)]).unwrap();
        assert_eq!(
            read(&db, oid, P::NUMBER_OF_STATES),
            PropertyValue::Unsigned(4)
        );
        // The first write applies, and the refused second changes nothing.
        assert!(out_of_range(wpm(&mut db, oid, &[labels(7), labels(1)])));
        assert_eq!(
            read(&db, oid, P::NUMBER_OF_STATES),
            PropertyValue::Unsigned(7)
        );
        assert_eq!(read(&db, oid, P::STATE_TEXT), labels(7));
    }
}
