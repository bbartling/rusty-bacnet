//! Color and Color Temperature over WriteProperty, WritePropertyMultiple,
//! ReadProperty and ReadPropertyMultiple (#887, #1386): Color_Command takes
//! and serves a BACnetColorCommand as written, refuses other datatypes and
//! broken encodings, and checks what each object allows (Addendum
//! 135-2020ca); the colour properties answer to their standard identifiers
//! past 4194303, and 508 to 511 no longer reach them.
//!
//! Field octets: the operation is context tag 0 (`09` with one octet), the
//! target colour two application REALs (`44`) between `1E` and `1F`, and the
//! target colour temperature, fade time, ramp rate and step increment
//! Unsigneds tags 2 to 5 (`29`/`2A`, `39`/`3A`/`3C`, `49`/`4A`, `59`/`5A`).

use super::lighting_required_rows::{assert_refused, db_with, read_wire, write_wire};
use super::*;
use bacnet_objects::color::{ColorObject, ColorTemperatureObject};
use bacnet_services::common::BACnetPropertyValue;
use bacnet_services::wpm::{WriteAccessSpecification, WritePropertyMultipleRequest};
use bacnet_types::constructed::{PropertyReference, ReadAccessSpecification};

const CC: PropertyIdentifier = PropertyIdentifier::COLOR_COMMAND;

/// WriteProperty of Color_Command carrying `value` as its octets.
fn write_raw(db: &mut ObjectDatabase, oid: ObjectIdentifier, value: &[u8]) -> Result<(), Error> {
    let mut request = BytesMut::new();
    WritePropertyRequest {
        object_identifier: oid,
        property_identifier: CC,
        property_array_index: None,
        property_value: value.to_vec(),
        priority: None,
    }
    .encode(&mut request)
    .unwrap();
    handle_write_property(db, &request).map(|_| ())
}

fn color() -> (ObjectDatabase, ObjectIdentifier) {
    db_with(Box::new(ColorObject::new(1, "CLR-1").unwrap()))
}

fn color_temperature() -> (ObjectDatabase, ObjectIdentifier) {
    db_with(Box::new(ColorTemperatureObject::new(1, "CT-1").unwrap()))
}

/// ReadProperty of the raw identifier `property`: the request octets and the
/// result.
fn read_raw(
    db: &ObjectDatabase,
    oid: ObjectIdentifier,
    property: u32,
) -> (Vec<u8>, Result<Vec<u8>, Error>) {
    let mut request = BytesMut::new();
    ReadPropertyRequest {
        object_identifier: oid,
        property_identifier: PropertyIdentifier::from_raw(property),
        property_array_index: None,
    }
    .encode(&mut request);
    let mut response = BytesMut::new();
    let result = handle_read_property(db, &request, &mut response).map(|_| {
        let ack = ReadPropertyACK::decode(&response).unwrap();
        assert_eq!(ack.property_identifier.to_raw(), property);
        ack.property_value
    });
    (request.to_vec(), result)
}

#[test]
fn color_command_reads_none_until_written_then_what_was_written() {
    let (mut db, oid) = color();
    assert_eq!(read_wire(&db, oid, CC), [0x09, 0x00]);
    let commands: [&[u8]; 4] = [
        // FADE_TO_COLOR to (0.5, 0.25) over 2,000 ms, and without a fade time.
        &[
            0x09, 0x01, 0x1E, 0x44, 0x3F, 0x00, 0x00, 0x00, 0x44, 0x3E, 0x80, 0x00, 0x00, 0x1F,
            0x3A, 0x07, 0xD0,
        ],
        &[
            0x09, 0x01, 0x1E, 0x44, 0x3F, 0x00, 0x00, 0x00, 0x44, 0x3E, 0x80, 0x00, 0x00, 0x1F,
        ],
        // STOP, and STOP with a fade time it doesn't use.
        &[0x09, 0x06],
        &[0x09, 0x06, 0x39, 0x05],
    ];
    for command in commands {
        write_raw(&mut db, oid, command).unwrap();
        assert_eq!(read_wire(&db, oid, CC), command, "{command:02X?}");
    }

    let (mut db, oid) = color_temperature();
    assert_eq!(read_wire(&db, oid, CC), [0x09, 0x00]);
    let commands: [&[u8]; 6] = [
        // FADE_TO_CCT to 2,700 K over 100 ms.
        &[0x09, 0x02, 0x2A, 0x0A, 0x8C, 0x39, 0x64],
        // RAMP_TO_CCT to 6,500 K at 30,000 K/s, and at the default rate.
        &[0x09, 0x03, 0x2A, 0x19, 0x64, 0x4A, 0x75, 0x30],
        &[0x09, 0x03, 0x2A, 0x19, 0x64],
        // STEP_UP_CCT by 1 K, STEP_DOWN_CCT by the default, STOP.
        &[0x09, 0x04, 0x59, 0x01],
        &[0x09, 0x05],
        &[0x09, 0x06],
    ];
    for command in commands {
        write_raw(&mut db, oid, command).unwrap();
        assert_eq!(read_wire(&db, oid, CC), command, "{command:02X?}");
    }
}

#[test]
fn color_command_refuses_other_datatypes_and_broken_encodings() {
    for (mut db, oid) in [color(), color_temperature()] {
        // An OCTET STRING, the form this property once took, is not a colour
        // command, nor is any other application-tagged value.
        for value in [
            PropertyValue::OctetString(vec![0x09, 0x06]),
            PropertyValue::Unsigned(2_700),
            PropertyValue::Enumerated(6),
        ] {
            assert_refused(
                write_wire(&mut db, oid, CC, value, None),
                ErrorCode::INVALID_DATA_TYPE,
            );
        }
        // Color_Command isn't commandable and has no NULL in its datatype, so
        // a NULL succeeds and leaves it as it is (#1396).
        write_wire(&mut db, oid, CC, PropertyValue::Null, None).unwrap();
        assert_eq!(read_wire(&db, oid, CC), [0x09, 0x00]);
        // A colour temperature without the operation before it.
        assert_refused(
            write_raw(&mut db, oid, &[0x2A, 0x0A, 0x8C]),
            ErrorCode::INVALID_DATA_TYPE,
        );
        let broken: [&[u8]; 7] = [
            // Fields out of order: fade time [3] before the target [2].
            &[0x09, 0x02, 0x39, 0x64, 0x2A, 0x0A, 0x8C],
            // A target colour of one REAL, and one given as a primitive [1].
            &[0x09, 0x01, 0x1E, 0x44, 0x3F, 0x00, 0x00, 0x00, 0x1F],
            &[0x09, 0x01, 0x1C, 0x3F, 0x00, 0x00, 0x00],
            // An undefined field [6].
            &[0x09, 0x04, 0x69, 0x01],
            // An operation with no content octets, and STOP in five octets
            // that open with zeros.
            &[0x08],
            &[0x0D, 0x05, 0x00, 0x00, 0x00, 0x00, 0x06],
            // A target colour temperature too wide for 32 bits with an
            // application NULL after it: the broken encoding outranks the
            // oversized field.
            &[0x09, 0x02, 0x2D, 0x05, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00],
        ];
        for value in broken {
            assert_refused(
                write_raw(&mut db, oid, value),
                ErrorCode::INVALID_DATA_ENCODING,
            );
        }
        assert_eq!(read_wire(&db, oid, CC), [0x09, 0x00]);
    }
}

#[test]
fn color_command_checks_what_each_object_takes() {
    // Taken by neither: NONE, an undefined operation and one too wide.
    let neither: [&[u8]; 3] = [
        &[0x09, 0x00],
        &[0x09, 0x07],
        &[0x0D, 0x05, 0x01, 0x00, 0x00, 0x00, 0x00],
    ];
    let color_refuses: [&[u8]; 9] = [
        // The Color Temperature operations.
        &[0x09, 0x02, 0x2A, 0x0A, 0x8C],
        &[0x09, 0x03, 0x2A, 0x0A, 0x8C],
        &[0x09, 0x04],
        &[0x09, 0x05],
        // FADE_TO_COLOR without a target, to x 1.5 (0x3FC00000), to y -0.5
        // (0xBF000000), over 99 ms and over 86,400,001 ms (0x05265C01).
        &[0x09, 0x01, 0x3A, 0x07, 0xD0],
        &[
            0x09, 0x01, 0x1E, 0x44, 0x3F, 0xC0, 0x00, 0x00, 0x44, 0x3E, 0x80, 0x00, 0x00, 0x1F,
        ],
        &[
            0x09, 0x01, 0x1E, 0x44, 0x3F, 0x00, 0x00, 0x00, 0x44, 0xBF, 0x00, 0x00, 0x00, 0x1F,
        ],
        &[
            0x09, 0x01, 0x1E, 0x44, 0x3F, 0x00, 0x00, 0x00, 0x44, 0x3E, 0x80, 0x00, 0x00, 0x1F,
            0x39, 0x63,
        ],
        &[
            0x09, 0x01, 0x1E, 0x44, 0x3F, 0x00, 0x00, 0x00, 0x44, 0x3E, 0x80, 0x00, 0x00, 0x1F,
            0x3C, 0x05, 0x26, 0x5C, 0x01,
        ],
    ];
    let temperature_refuses: [&[u8]; 9] = [
        // FADE_TO_COLOR, even with a valid target.
        &[
            0x09, 0x01, 0x1E, 0x44, 0x3F, 0x00, 0x00, 0x00, 0x44, 0x3E, 0x80, 0x00, 0x00, 0x1F,
        ],
        // FADE_TO_CCT and RAMP_TO_CCT without a target, to 999 K (0x03E7) and
        // to 30,001 K (0x7531).
        &[0x09, 0x02, 0x39, 0x64],
        &[0x09, 0x03],
        &[0x09, 0x02, 0x2A, 0x03, 0xE7],
        &[0x09, 0x03, 0x2A, 0x75, 0x31],
        // A fade time of 99 ms, a ramp rate of 0 and of 30,001, and a step
        // increment of 0.
        &[0x09, 0x02, 0x2A, 0x0A, 0x8C, 0x39, 0x63],
        &[0x09, 0x03, 0x2A, 0x0A, 0x8C, 0x49, 0x00],
        &[0x09, 0x03, 0x2A, 0x0A, 0x8C, 0x4A, 0x75, 0x31],
        &[0x09, 0x05, 0x59, 0x00],
    ];
    for ((mut db, oid), refused) in [
        (color(), [&neither[..], &color_refuses[..]].concat()),
        (
            color_temperature(),
            [&neither[..], &temperature_refuses[..]].concat(),
        ),
    ] {
        for value in refused {
            assert_refused(
                write_raw(&mut db, oid, value),
                ErrorCode::VALUE_OUT_OF_RANGE,
            );
        }
        assert_eq!(read_wire(&db, oid, CC), [0x09, 0x00]);
    }
}

#[test]
fn color_properties_answer_to_their_standard_identifiers() {
    let (db, oid) = color();
    // Default_Color is 4194330 (0x40001A), three octets under tag [1] of the
    // request; it reads as the D65 xy colour.
    let (request, value) = read_raw(&db, oid, 4_194_330);
    assert_eq!(request[5..], [0x1B, 0x40, 0x00, 0x1A]);
    assert_eq!(
        value.unwrap(),
        [0x44, 0x3E, 0xA0, 0x1A, 0x37, 0x44, 0x3E, 0xA8, 0x72, 0xB0]
    );
    // Color_Command is 4194334 (0x40001E).
    let (request, value) = read_raw(&db, oid, 4_194_334);
    assert_eq!(request[5..], [0x1B, 0x40, 0x00, 0x1E]);
    assert_eq!(value.unwrap(), [0x09, 0x00]);

    let (db, oid) = color_temperature();
    // Default_Color_Temperature is 4194331 (0x40001B): 4,000 K.
    let (request, value) = read_raw(&db, oid, 4_194_331);
    assert_eq!(request[5..], [0x1B, 0x40, 0x00, 0x1B]);
    assert_eq!(value.unwrap(), [0x22, 0x0F, 0xA0]);
    assert_eq!(read_raw(&db, oid, 4_194_334).1.unwrap(), [0x09, 0x00]);
}

#[test]
fn color_objects_no_longer_answer_to_508_to_511() {
    // 508 to 511 name Network Port properties (Addendum 135-2020cc).
    assert_eq!(
        [508, 509, 510, 511].map(|raw| PropertyIdentifier::from_raw(raw).to_string()),
        [
            "ADDITIONAL_REFERENCE_PORTS",
            "CERTIFICATE_SIGNING_REQUEST_FILE",
            "COMMAND_VALIDATION_RESULT",
            "ISSUER_CERTIFICATE_FILES",
        ]
    );
    for (db, oid) in [color(), color_temperature()] {
        for raw in [508, 509, 510, 511] {
            assert_refused(
                read_raw(&db, oid, raw).1.map(|_| ()),
                ErrorCode::UNKNOWN_PROPERTY,
            );
        }
        // Nor does the old Color_Command write, an OCTET STRING to 508.
        let mut db = db;
        assert_refused(
            write_wire(
                &mut db,
                oid,
                PropertyIdentifier::from_raw(508),
                PropertyValue::OctetString(vec![0x09, 0x06]),
                None,
            ),
            ErrorCode::UNKNOWN_PROPERTY,
        );
        assert_eq!(read_wire(&db, oid, CC), [0x09, 0x00]);
    }
}

/// WritePropertyMultiple of `(property, octets)` pairs to `oid`.
fn write_multiple(
    db: &mut ObjectDatabase,
    oid: ObjectIdentifier,
    writes: &[(PropertyIdentifier, &[u8])],
) -> Result<(), Error> {
    let mut request = BytesMut::new();
    WritePropertyMultipleRequest {
        list_of_write_access_specs: vec![WriteAccessSpecification {
            object_identifier: oid,
            list_of_properties: writes
                .iter()
                .map(|&(property_identifier, value)| BACnetPropertyValue {
                    property_identifier,
                    property_array_index: None,
                    value: value.to_vec(),
                    priority: None,
                })
                .collect(),
        }],
    }
    .encode(&mut request)
    .unwrap();
    handle_write_property_multiple(db, &request).map(|_| ())
}

#[test]
fn color_command_over_write_property_multiple() {
    // FADE_TO_COLOR to (0.5, 0.25) over 2,000 ms, beside Default_Fade_Time
    // 1,000 ms; both commit.
    let fade: &[u8] = &[
        0x09, 0x01, 0x1E, 0x44, 0x3F, 0x00, 0x00, 0x00, 0x44, 0x3E, 0x80, 0x00, 0x00, 0x1F, 0x3A,
        0x07, 0xD0,
    ];
    let (mut db, oid) = color();
    write_multiple(
        &mut db,
        oid,
        &[
            (CC, fade),
            (PropertyIdentifier::DEFAULT_FADE_TIME, &[0x22, 0x03, 0xE8]),
        ],
    )
    .unwrap();
    assert_eq!(read_wire(&db, oid, CC), fade);
    assert_eq!(
        read_wire(&db, oid, PropertyIdentifier::DEFAULT_FADE_TIME),
        [0x22, 0x03, 0xE8]
    );
    // STOP commits before NONE is refused, as WritePropertyMultiple keeps the
    // prefix it wrote.
    assert_refused(
        write_multiple(&mut db, oid, &[(CC, &[0x09, 0x06]), (CC, &[0x09, 0x00])]),
        ErrorCode::VALUE_OUT_OF_RANGE,
    );
    assert_eq!(read_wire(&db, oid, CC), [0x09, 0x06]);

    let (mut db, oid) = color_temperature();
    // The old OCTET STRING form is refused; RAMP_TO_CCT to 6,500 K is taken.
    assert_refused(
        write_multiple(&mut db, oid, &[(CC, &[0x62, 0x09, 0x06])]),
        ErrorCode::INVALID_DATA_TYPE,
    );
    let ramp: &[u8] = &[0x09, 0x03, 0x2A, 0x19, 0x64];
    write_multiple(&mut db, oid, &[(CC, ramp)]).unwrap();
    assert_eq!(read_wire(&db, oid, CC), ramp);
}

#[test]
fn color_properties_over_read_property_multiple() {
    let (db, oid) = color();
    let references = [4_194_330, 4_194_334, 4_194_331, 510].map(|raw| PropertyReference {
        property_identifier: PropertyIdentifier::from_raw(raw),
        property_array_index: None,
    });
    let mut request = BytesMut::new();
    ReadPropertyMultipleRequest {
        list_of_read_access_specs: vec![ReadAccessSpecification {
            object_identifier: oid,
            list_of_property_references: references.to_vec(),
        }],
    }
    .encode(&mut request)
    .unwrap();
    // Color 1 is 0x0FC00001. Each identifier past 4194303 takes three
    // octets under tag [0]; 510 (0x01FE) takes two.
    assert_eq!(
        request.as_ref(),
        [
            0x0C, 0x0F, 0xC0, 0x00, 0x01, 0x1E, 0x0B, 0x40, 0x00, 0x1A, 0x0B, 0x40, 0x00, 0x1E,
            0x0B, 0x40, 0x00, 0x1B, 0x0A, 0x01, 0xFE, 0x1F,
        ]
    );
    let mut response = BytesMut::new();
    handle_read_property_multiple(&db, &request, &mut response).unwrap();
    let ack = ReadPropertyMultipleACK::decode(&response).unwrap();
    let results = &ack.list_of_read_access_results[0].list_of_results;
    let properties: Vec<_> = results.iter().map(|r| r.property_identifier).collect();
    assert_eq!(properties, references.map(|r| r.property_identifier));
    // Default_Color is the D65 xy colour and Color_Command NONE.
    assert_eq!(
        results[0].property_value.as_deref(),
        Some(&[0x44, 0x3E, 0xA0, 0x1A, 0x37, 0x44, 0x3E, 0xA8, 0x72, 0xB0][..])
    );
    assert_eq!(
        results[1].property_value.as_deref(),
        Some(&[0x09, 0x00][..])
    );
    // A Color has no Default_Color_Temperature, and 510 is a Network Port
    // property.
    for result in &results[2..] {
        assert_eq!(
            result.error,
            Some((ErrorClass::PROPERTY, ErrorCode::UNKNOWN_PROPERTY))
        );
    }
}
