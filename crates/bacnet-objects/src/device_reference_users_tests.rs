//! Every writable device reference property answers the same value the same
//! way (#1313, #1308): one table of local, empty, non-Device, malformed and
//! wrong-datatype values, written to each property through the shared
//! helpers. A refused value leaves the property as it was. The setters'
//! table is `device_reference_setter_tests.rs`.

use std::sync::Arc;

use bacnet_types::constructed::BACnetStageLimitValue;
use bacnet_types::enums::{ErrorClass, ObjectType, PropertyIdentifier};
use bacnet_types::primitives::{Date, Time};

use super::*;
use crate::averaging::AveragingObject;
use crate::channel::ChannelObject;
use crate::clock::{ClockFrame, ClockReader};
use crate::schedule::ScheduleObject;
use crate::staging::{StagingConfig, StagingObject};
use crate::traits::BACnetObject;
use crate::trend::{TrendLogMultipleObject, TrendLogObject};

type P = PropertyIdentifier;

const EMPTY: u32 = ObjectIdentifier::WILDCARD_INSTANCE;

fn oid(object_type: ObjectType, instance: u32) -> ObjectIdentifier {
    ObjectIdentifier::new(object_type, instance).unwrap()
}

/// A clock for the trend logs, whose reference change purges the buffer
/// with a time-stamped record.
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

/// The class and code of a refusal, whether or not it names an element.
fn class_and_code(error: &Error) -> (u32, u32) {
    match error {
        Error::Protocol { class, code } | Error::Structured { class, code, .. } => (*class, *code),
        other => panic!("expected a protocol error, got {other:?}"),
    }
}

fn property_code(code: ErrorCode) -> Option<(u32, u32)> {
    Some((ErrorClass::PROPERTY.to_raw() as u32, code.to_raw() as u32))
}

/// Which Clause 21 production the property holds.
#[derive(Clone, Copy)]
enum Production {
    Property,
    Object,
}

/// The encoding of one reference to `object`, with `device` as its Device
/// member.
fn encoded(
    production: Production,
    object: ObjectIdentifier,
    device: Option<ObjectIdentifier>,
) -> Vec<u8> {
    match production {
        Production::Property => {
            let reference = BACnetDeviceObjectPropertyReference {
                object_identifier: object,
                property_identifier: P::PRESENT_VALUE.to_raw(),
                property_array_index: None,
                device_identifier: device,
            };
            match reference_value(&reference) {
                PropertyValue::ApplicationData(bytes) => bytes,
                _ => unreachable!(),
            }
        }
        Production::Object => match reference_value(&BACnetDeviceObjectReference {
            device_identifier: device,
            object_identifier: object,
        }) {
            PropertyValue::ApplicationData(bytes) => bytes,
            _ => unreachable!(),
        },
    }
}

/// One writable device reference property, on a fresh object holding one
/// valid reference to `target`.
struct Writable {
    name: &'static str,
    build: fn() -> Box<dyn BACnetObject>,
    property: PropertyIdentifier,
    index: Option<u32>,
    production: Production,
    target: ObjectType,
    /// The value holds exactly one reference (a single reference, or one
    /// array element by index).
    single: bool,
}

fn averaging() -> Box<dyn BACnetObject> {
    Box::new(AveragingObject::new(1, "AVG-1").unwrap())
}

fn trend_log() -> Box<dyn BACnetObject> {
    let mut log = TrendLogObject::new(1, "TL-1", 8).unwrap();
    log.bind_clock_internal(Some(Arc::new(FixedClock)));
    Box::new(log)
}

fn trend_log_multiple() -> Box<dyn BACnetObject> {
    let mut log = TrendLogMultipleObject::new(1, "TLM-1", 8).unwrap();
    log.add_property_reference(BACnetDeviceObjectPropertyReference::new_local(
        oid(ObjectType::ANALOG_INPUT, 1),
        P::PRESENT_VALUE.to_raw(),
    ))
    .unwrap();
    log.bind_clock_internal(Some(Arc::new(FixedClock)));
    Box::new(log)
}

fn channel() -> Box<dyn BACnetObject> {
    let mut channel = ChannelObject::new(1, "CH-1", 1).unwrap();
    channel
        .set_members(vec![BACnetDeviceObjectPropertyReference::new_local(
            oid(ObjectType::ANALOG_OUTPUT, 1),
            P::PRESENT_VALUE.to_raw(),
        )])
        .unwrap();
    Box::new(channel)
}

fn schedule() -> Box<dyn BACnetObject> {
    Box::new(ScheduleObject::new(1, "SCH-1", PropertyValue::Real(0.0)).unwrap())
}

fn staging() -> Box<dyn BACnetObject> {
    let stage = |limit, active| BACnetStageLimitValue {
        limit,
        values: vec![active],
        deadband: 1.0,
    };
    let config = StagingConfig {
        present_value: 5.0,
        min_present_value: -1.0,
        units: 62,
        priority_for_writing: 8,
        stages: vec![stage(10.0, false), stage(20.0, true)],
        target_references: vec![oid(ObjectType::BINARY_OUTPUT, 1).into()],
        stage_names: None,
    };
    Box::new(StagingObject::new(1, "STG-1", config).unwrap())
}

const WRITABLE: [Writable; 9] = [
    Writable {
        name: "Averaging Object_Property_Reference",
        build: averaging,
        property: P::OBJECT_PROPERTY_REFERENCE,
        index: None,
        production: Production::Property,
        target: ObjectType::ANALOG_INPUT,
        single: true,
    },
    Writable {
        name: "Trend Log Log_DeviceObjectProperty",
        build: trend_log,
        property: P::LOG_DEVICE_OBJECT_PROPERTY,
        index: None,
        production: Production::Property,
        target: ObjectType::ANALOG_INPUT,
        single: true,
    },
    Writable {
        name: "Trend Log Multiple Log_DeviceObjectProperty[1]",
        build: trend_log_multiple,
        property: P::LOG_DEVICE_OBJECT_PROPERTY,
        index: Some(1),
        production: Production::Property,
        target: ObjectType::ANALOG_INPUT,
        single: true,
    },
    Writable {
        name: "Trend Log Multiple Log_DeviceObjectProperty",
        build: trend_log_multiple,
        property: P::LOG_DEVICE_OBJECT_PROPERTY,
        index: None,
        production: Production::Property,
        target: ObjectType::ANALOG_INPUT,
        single: false,
    },
    Writable {
        name: "Channel List_Of_Object_Property_References[1]",
        build: channel,
        property: P::LIST_OF_OBJECT_PROPERTY_REFERENCES,
        index: Some(1),
        production: Production::Property,
        target: ObjectType::ANALOG_OUTPUT,
        single: true,
    },
    Writable {
        name: "Channel List_Of_Object_Property_References",
        build: channel,
        property: P::LIST_OF_OBJECT_PROPERTY_REFERENCES,
        index: None,
        production: Production::Property,
        target: ObjectType::ANALOG_OUTPUT,
        single: false,
    },
    Writable {
        name: "Schedule List_Of_Object_Property_References",
        build: schedule,
        property: P::LIST_OF_OBJECT_PROPERTY_REFERENCES,
        index: None,
        production: Production::Property,
        target: ObjectType::ANALOG_VALUE,
        single: false,
    },
    Writable {
        name: "Staging Target_References[1]",
        build: staging,
        property: P::TARGET_REFERENCES,
        index: Some(1),
        production: Production::Object,
        target: ObjectType::BINARY_OUTPUT,
        single: true,
    },
    Writable {
        name: "Staging Target_References",
        build: staging,
        property: P::TARGET_REFERENCES,
        index: None,
        production: Production::Object,
        target: ObjectType::BINARY_OUTPUT,
        single: false,
    },
];

/// One row of the write table: the value, built for a user, and the answer
/// every user gives it (`None` for acceptance).
struct Row {
    what: &'static str,
    single_only: bool,
    value: fn(&Writable) -> PropertyValue,
    expected: Option<(u32, u32)>,
}

fn reference_to(user: &Writable, instance: u32, device: Option<ObjectIdentifier>) -> Vec<u8> {
    encoded(user.production, oid(user.target, instance), device)
}

fn rows() -> Vec<Row> {
    vec![
        Row {
            what: "a reference to an object in this device",
            single_only: false,
            value: |user| PropertyValue::ApplicationData(reference_to(user, 2, None)),
            expected: None,
        },
        Row {
            what: "the empty object instance 4194303",
            single_only: false,
            value: |user| PropertyValue::ApplicationData(reference_to(user, EMPTY, None)),
            expected: None,
        },
        Row {
            what: "a non-Device device identifier",
            single_only: false,
            value: |user| {
                let device = Some(oid(ObjectType::ANALOG_VALUE, 9));
                PropertyValue::ApplicationData(reference_to(user, 2, device))
            },
            expected: property_code(ErrorCode::VALUE_OUT_OF_RANGE),
        },
        Row {
            what: "a non-Device device identifier at the empty instance",
            single_only: false,
            value: |user| {
                let device = Some(oid(ObjectType::ANALOG_VALUE, EMPTY));
                PropertyValue::ApplicationData(reference_to(user, EMPTY, device))
            },
            expected: property_code(ErrorCode::VALUE_OUT_OF_RANGE),
        },
        Row {
            what: "a second reference in a single-reference value",
            single_only: true,
            value: |user| {
                let one = reference_to(user, 2, None);
                PropertyValue::ApplicationData([one.clone(), one].concat())
            },
            expected: property_code(ErrorCode::INVALID_DATA_ENCODING),
        },
        Row {
            what: "a truncated reference",
            single_only: false,
            value: |user| {
                let one = reference_to(user, 2, None);
                PropertyValue::ApplicationData(one[..one.len() - 1].to_vec())
            },
            expected: property_code(ErrorCode::INVALID_DATA_ENCODING),
        },
        Row {
            what: "an element after the reference that can't open one",
            single_only: false,
            value: |user| {
                PropertyValue::ApplicationData(
                    [reference_to(user, 2, None), vec![0x49, 0x01]].concat(),
                )
            },
            expected: property_code(ErrorCode::INVALID_DATA_TYPE),
        },
        Row {
            what: "a REAL",
            single_only: false,
            value: |_| PropertyValue::Real(1.0),
            expected: property_code(ErrorCode::INVALID_DATA_TYPE),
        },
        Row {
            what: "an application-tagged object identifier",
            single_only: false,
            value: |user| {
                let id = oid(user.target, 2);
                let mut bytes = vec![0xC4];
                bytes.extend_from_slice(&id.encode());
                PropertyValue::ApplicationData(bytes)
            },
            expected: property_code(ErrorCode::INVALID_DATA_TYPE),
        },
    ]
}

#[test]
fn every_writable_device_reference_answers_the_same_value_the_same_way() {
    for user in &WRITABLE {
        for row in rows() {
            if row.single_only && !user.single {
                continue;
            }
            let mut object = (user.build)();
            let before = object.read_property(user.property, user.index).unwrap();
            let result = object.write_property(user.property, user.index, (row.value)(user), None);
            let context = format!("{}: {}", user.name, row.what);
            match row.expected {
                None => result.unwrap_or_else(|error| panic!("{context}: refused with {error:?}")),
                Some(expected) => {
                    let error = result.expect_err(&context);
                    assert_eq!(class_and_code(&error), expected, "{context}: {error:?}");
                    assert_eq!(
                        object.read_property(user.property, user.index).unwrap(),
                        before,
                        "{context}: a refused value changes nothing"
                    );
                }
            }
        }
    }
}
