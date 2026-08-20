//! GetEnrollmentSummary Event State Filter semantics (Clause 13.11.1.1).

use super::*;
use bacnet_objects::traits::BACnetObject;
use bacnet_services::enrollment_summary::{GetEnrollmentSummaryAck, GetEnrollmentSummaryRequest};
use bacnet_types::enums::EnrollmentSummaryEventStateFilter;

struct EnrollmentAtState {
    oid: ObjectIdentifier,
    event_state: EventState,
}

impl BACnetObject for EnrollmentAtState {
    fn object_identifier(&self) -> ObjectIdentifier {
        self.oid
    }

    fn object_name(&self) -> &str {
        "EnrollmentAtState"
    }

    fn read_property(
        &self,
        property: PropertyIdentifier,
        _array_index: Option<u32>,
    ) -> Result<PropertyValue, Error> {
        match property {
            p if p == PropertyIdentifier::EVENT_STATE => {
                Ok(PropertyValue::Enumerated(self.event_state.to_raw()))
            }
            p if p == PropertyIdentifier::EVENT_DETECTION_ENABLE => {
                Ok(PropertyValue::Boolean(true))
            }
            p if p == PropertyIdentifier::NOTIFICATION_CLASS => Ok(PropertyValue::Unsigned(7)),
            _ => Err(Error::Protocol {
                class: bacnet_types::enums::ErrorClass::PROPERTY.to_raw() as u32,
                code: bacnet_types::enums::ErrorCode::UNKNOWN_PROPERTY.to_raw() as u32,
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
            class: bacnet_types::enums::ErrorClass::PROPERTY.to_raw() as u32,
            code: bacnet_types::enums::ErrorCode::WRITE_ACCESS_DENIED.to_raw() as u32,
        })
    }

    fn property_list(&self) -> std::borrow::Cow<'static, [PropertyIdentifier]> {
        static PROPERTIES: &[PropertyIdentifier] = &[
            PropertyIdentifier::EVENT_STATE,
            PropertyIdentifier::EVENT_DETECTION_ENABLE,
            PropertyIdentifier::NOTIFICATION_CLASS,
        ];
        std::borrow::Cow::Borrowed(PROPERTIES)
    }
}

fn entry_count(actual: EventState, filter_raw: Option<u32>) -> usize {
    let mut db = ObjectDatabase::new();
    db.add(Box::new(EnrollmentAtState {
        oid: ObjectIdentifier::new(ObjectType::EVENT_ENROLLMENT, 1).unwrap(),
        event_state: actual,
    }))
    .unwrap();

    let request = GetEnrollmentSummaryRequest {
        acknowledgment_filter: 0,
        enrollment_filter: None,
        event_state_filter: filter_raw.map(EnrollmentSummaryEventStateFilter::from_raw),
        event_type_filter: None,
        priority_filter: None,
        notification_class_filter: None,
    };
    let mut request_bytes = BytesMut::new();
    request.encode(&mut request_bytes);
    let mut response = BytesMut::new();
    handle_get_enrollment_summary(&db, &request_bytes, &mut response).unwrap();
    let ack = GetEnrollmentSummaryAck::decode(&response).unwrap();
    assert!(ack
        .entries
        .iter()
        .all(|entry| entry.notification_class == Some(7)));
    ack.entries.len()
}

#[test]
fn event_state_filter_values_have_service_specific_meanings() {
    assert_eq!(entry_count(EventState::OFFNORMAL, Some(0)), 1);
    assert_eq!(entry_count(EventState::NORMAL, Some(0)), 0);

    assert_eq!(entry_count(EventState::FAULT, Some(1)), 1);

    assert_eq!(entry_count(EventState::NORMAL, Some(2)), 1);
    assert_eq!(entry_count(EventState::OFFNORMAL, Some(2)), 0);

    assert_eq!(entry_count(EventState::NORMAL, Some(3)), 1);
    assert_eq!(entry_count(EventState::HIGH_LIMIT, Some(3)), 1);

    assert_eq!(entry_count(EventState::FAULT, Some(4)), 1);
    assert_eq!(entry_count(EventState::HIGH_LIMIT, Some(4)), 1);
    assert_eq!(entry_count(EventState::NORMAL, Some(4)), 0);
}

#[test]
fn omitted_event_state_filter_defaults_to_all() {
    assert_eq!(entry_count(EventState::NORMAL, None), 1);
    assert_eq!(entry_count(EventState::HIGH_LIMIT, None), 1);
}
