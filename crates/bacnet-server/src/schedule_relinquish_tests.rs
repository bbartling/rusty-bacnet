//! A Schedule's NULL on its targets (#1416): it relinquishes the Schedule's
//! slot in a commandable Present_Value, and on a property that isn't
//! commandable and has no NULL in its datatype it is the no-op WriteProperty
//! makes of it, the target counting as one that took the write. A target
//! that refuses for any other reason still fails.

use std::borrow::Cow;
use std::sync::Mutex;

use bacnet_objects::analog::{AnalogInputObject, AnalogOutputObject};
use bacnet_objects::device::{DeviceConfig, DeviceObject};
use bacnet_objects::traits::BACnetObject;
use bacnet_types::constructed::BACnetObjectPropertyReference;
use bacnet_types::enums::{ErrorClass, ErrorCode};
use bacnet_types::error::Error;
use ScheduleTargetOutcome::{Accepted, Failed};

use super::*;

fn oid(object_type: ObjectType, instance: u32) -> ObjectIdentifier {
    ObjectIdentifier::new(object_type, instance).unwrap()
}

fn sch() -> ObjectIdentifier {
    oid(ObjectType::SCHEDULE, 1)
}

fn ai() -> ObjectIdentifier {
    oid(ObjectType::ANALOG_INPUT, 1)
}

fn ao() -> ObjectIdentifier {
    oid(ObjectType::ANALOG_OUTPUT, 2)
}

/// How the targets took each of a Schedule's writes, in order.
type Outcomes = Arc<Mutex<Vec<Vec<ScheduleTargetOutcome>>>>;

/// A Schedule that owes the writes it was built with, and keeps how the
/// targets took each.
struct OwingSchedule {
    owed: Vec<ScheduleWrite>,
    outcomes: Outcomes,
}

impl BACnetObject for OwingSchedule {
    fn object_identifier(&self) -> ObjectIdentifier {
        sch()
    }

    fn object_name(&self) -> &str {
        "SCH-1"
    }

    fn read_property(
        &self,
        property: PropertyIdentifier,
        _array_index: Option<u32>,
    ) -> Result<PropertyValue, Error> {
        match property {
            p if p == PropertyIdentifier::OBJECT_IDENTIFIER => {
                Ok(PropertyValue::ObjectIdentifier(sch()))
            }
            p if p == PropertyIdentifier::OBJECT_NAME => {
                Ok(PropertyValue::CharacterString("SCH-1".into()))
            }
            p if p == PropertyIdentifier::OBJECT_TYPE => {
                Ok(PropertyValue::Enumerated(ObjectType::SCHEDULE.to_raw()))
            }
            _ => Err(Error::Protocol {
                class: ErrorClass::PROPERTY.to_raw() as u32,
                code: ErrorCode::UNKNOWN_PROPERTY.to_raw() as u32,
            }),
        }
    }

    fn write_property(
        &mut self,
        _property: PropertyIdentifier,
        _array_index: Option<u32>,
        _value: PropertyValue,
        _priority: Option<u8>,
    ) -> Result<(), Error> {
        Err(Error::Protocol {
            class: ErrorClass::PROPERTY.to_raw() as u32,
            code: ErrorCode::WRITE_ACCESS_DENIED.to_raw() as u32,
        })
    }

    fn property_list(&self) -> Cow<'static, [PropertyIdentifier]> {
        Cow::Borrowed(&[])
    }

    fn take_owed_schedule_writes(&mut self) -> Vec<ScheduleWrite> {
        std::mem::take(&mut self.owed)
    }

    fn complete_schedule_write(
        &mut self,
        _write: &ScheduleWrite,
        outcomes: &[ScheduleTargetOutcome],
    ) -> bool {
        self.outcomes.lock().unwrap().push(outcomes.to_vec());
        false
    }
}

fn reference(
    object: ObjectIdentifier,
    property: PropertyIdentifier,
) -> BACnetObjectPropertyReference {
    BACnetObjectPropertyReference::new(object, property.to_raw())
}

fn read(
    db: &ObjectDatabase,
    object: ObjectIdentifier,
    property: PropertyIdentifier,
    index: Option<u32>,
) -> PropertyValue {
    db.get(&object)
        .unwrap()
        .read_property(property, index)
        .unwrap()
}

#[tokio::test]
async fn a_schedule_null_relinquishes_a_commandable_target_and_leaves_the_others_as_they_are() {
    use PropertyIdentifier as P;
    let outcomes = Outcomes::default();
    // Both writes are owed ones, which go out without a clock: a Real at
    // priority 9, then the NULL that relinquishes it.
    let write = |value, references| ScheduleWrite {
        value,
        priority: 9,
        references,
    };
    let schedule = OwingSchedule {
        owed: vec![
            write(
                PropertyValue::Real(5.0),
                vec![
                    reference(ao(), P::PRESENT_VALUE),
                    reference(ai(), P::COV_INCREMENT),
                ],
            ),
            write(
                PropertyValue::Null,
                vec![
                    // Commandable: the slot is relinquished.
                    reference(ao(), P::PRESENT_VALUE),
                    // Not commandable, and a REAL has no NULL: left as it is.
                    reference(ai(), P::COV_INCREMENT),
                    // Read-only: still refused.
                    reference(ai(), P::STATUS_FLAGS),
                    // No such object.
                    reference(oid(ObjectType::ANALOG_INPUT, 9), P::PRESENT_VALUE),
                ],
            ),
        ],
        outcomes: Arc::clone(&outcomes),
    };
    let mut db = ObjectDatabase::new();
    db.add(Box::new(
        DeviceObject::new(DeviceConfig::default()).unwrap(),
    ))
    .unwrap();
    db.add(Box::new(AnalogInputObject::new(1, "AI-1", 62).unwrap()))
        .unwrap();
    db.add(Box::new(AnalogOutputObject::new(2, "AO-2", 62).unwrap()))
        .unwrap();
    db.add(Box::new(schedule)).unwrap();
    let db = Arc::new(RwLock::new(db));

    tick_schedules(&db).await;

    assert_eq!(
        *outcomes.lock().unwrap(),
        [
            vec![Accepted, Accepted],
            vec![Accepted, Accepted, Failed, Failed]
        ]
    );
    let db = db.read().await;
    assert_eq!(
        read(&db, ao(), P::PRIORITY_ARRAY, Some(9)),
        PropertyValue::Null
    );
    assert_eq!(
        read(&db, ao(), P::PRESENT_VALUE, None),
        PropertyValue::Real(0.0)
    );
    assert_eq!(
        read(&db, ai(), P::COV_INCREMENT, None),
        PropertyValue::Real(5.0)
    );
}
