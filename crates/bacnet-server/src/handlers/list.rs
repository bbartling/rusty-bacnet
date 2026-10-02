use super::*;
use bacnet_encoding::{constructed::decode_destination_list, primitives::decode_application_value};
use bacnet_services::list_manipulation::ListElementRequest;
use bacnet_types::constructed::BACnetDestination;

fn protocol_error(class: ErrorClass, code: ErrorCode) -> Error {
    Error::Protocol {
        class: class.to_raw() as u32,
        code: code.to_raw() as u32,
    }
}

fn invalid_data_type() -> Error {
    protocol_error(ErrorClass::PROPERTY, ErrorCode::INVALID_DATA_TYPE)
}

/// Handle an AddListElement request.
///
/// Reads the target property, appends the new elements, and writes back.
pub fn handle_add_list_element(db: &mut ObjectDatabase, service_data: &[u8]) -> Result<(), Error> {
    handle_list_element_observed(db, service_data, false, |_, _, _| {})
}

/// Handle a RemoveListElement request.
///
/// Reads the target property, removes matching elements, and writes back.
pub fn handle_remove_list_element(
    db: &mut ObjectDatabase,
    service_data: &[u8],
) -> Result<(), Error> {
    handle_list_element_observed(db, service_data, true, |_, _, _| {})
}

/// How a list's elements travel in the request and how the object holds them.
#[derive(Clone, Copy)]
enum ElementCodec {
    /// Consecutive application-tagged values, held as `PropertyValue::List`.
    Values,
    /// BACnetDestination entries, held as the framed list in `ApplicationData`.
    Destinations,
}

impl ElementCodec {
    /// The codec the property's datatype implies, known even when the object
    /// is missing. Only a BACnetLIST of BACnetDestination, the Recipient_List
    /// of Notification Class and Notification Forwarder (Tables 12-24 and
    /// 12-58), takes the destination codec.
    fn for_datatype(object_type: ObjectType, property: PropertyIdentifier) -> Self {
        let destinations = property == PropertyIdentifier::RECIPIENT_LIST
            && matches!(
                object_type,
                ObjectType::NOTIFICATION_CLASS | ObjectType::NOTIFICATION_FORWARDER
            );
        if destinations {
            Self::Destinations
        } else {
            Self::Values
        }
    }

    /// Whether the object holds the list in the form this codec edits.
    fn holds(self, stored: &PropertyValue) -> bool {
        match self {
            Self::Values => matches!(stored, PropertyValue::List(_)),
            Self::Destinations => matches!(stored, PropertyValue::ApplicationData(_)),
        }
    }

    fn decode(self, elements: &[u8]) -> Result<ListEdits, Error> {
        match self {
            Self::Destinations => decode_destination_list(elements).map(ListEdits::Destinations),
            Self::Values => {
                let mut values = Vec::new();
                let mut offset = 0;
                while offset < elements.len() {
                    let (value, next) = decode_application_value(elements, offset)?;
                    values.push(value);
                    offset = next;
                }
                Ok(ListEdits::Values(values))
            }
        }
    }
}

enum ListEdits {
    Values(Vec<PropertyValue>),
    Destinations(Vec<BACnetDestination>),
}

/// A request refused before any element is applied. `current` is the target
/// property's value when it could be read, kept for the observer's pre-image.
struct Refusal {
    error: Error,
    current: Option<PropertyValue>,
}

impl Refusal {
    fn unread(error: Error) -> Self {
        Self {
            error,
            current: None,
        }
    }

    fn read(class: ErrorClass, code: ErrorCode, current: PropertyValue) -> Self {
        Self {
            error: protocol_error(class, code),
            current: Some(current),
        }
    }
}

/// Resolve the target list without looking at the elements. The checks run in
/// the order the service procedures of Clauses 15.1 and 15.2 imply: the
/// object, the property, a supplied array index, and then whether the target
/// is a BACnetLIST at all. Element datatype errors come only after every one
/// of these has passed.
fn list_target(
    db: &ObjectDatabase,
    request: &ListElementRequest,
    codec: ElementCodec,
) -> Result<PropertyValue, Refusal> {
    let object = db.get(&request.object_identifier).ok_or_else(|| {
        Refusal::unread(protocol_error(
            ErrorClass::OBJECT,
            ErrorCode::UNKNOWN_OBJECT,
        ))
    })?;
    let property = request.property_identifier;
    let index = request.property_array_index;
    let read = |index| {
        object
            .read_property(property, index)
            .map_err(Refusal::unread)
    };
    if index.is_some() && !object.is_array_property(property) {
        // Read the whole property first so an unknown one keeps its error.
        return Err(Refusal::read(
            ErrorClass::PROPERTY,
            ErrorCode::PROPERTY_IS_NOT_AN_ARRAY,
            read(None)?,
        ));
    }
    let current = read(index)?;
    // An indexed array element is never a list: 135-2020 defines no
    // BACnetARRAY of BACnetLIST property.
    if index.is_some() || !object.is_list_property(property) {
        return Err(Refusal::read(
            ErrorClass::SERVICES,
            ErrorCode::PROPERTY_IS_NOT_A_LIST,
            current,
        ));
    }
    if !codec.holds(&current) {
        // A list held in a form neither codec edits, such as a framed list of
        // references, cannot change through these services.
        return Err(Refusal::read(
            ErrorClass::PROPERTY,
            ErrorCode::WRITE_ACCESS_DENIED,
            current,
        ));
    }
    Ok(current)
}

/// Decode once and observe only executable requests. The callback borrows the
/// pre-image already needed by execution; it never causes a second property read.
/// Target errors (lookup, read, array index, not a list) keep their precedence
/// over element decode errors.
pub(crate) fn handle_list_element_observed(
    db: &mut ObjectDatabase,
    service_data: &[u8],
    remove: bool,
    mut before: impl FnMut(&ObjectDatabase, &ListElementRequest, Option<&PropertyValue>),
) -> Result<(), Error> {
    let request = ListElementRequest::decode(service_data)?;
    let codec = ElementCodec::for_datatype(
        request.object_identifier.object_type(),
        request.property_identifier,
    );
    let target = list_target(db, &request, codec);
    // Every request decodes its elements once, with the codec its datatype
    // implies; a refused request reaches the observer only if they decode.
    let edits = codec.decode(&request.list_of_elements);
    let current = match target {
        Ok(current) => current,
        Err(Refusal { error, current }) => {
            if edits.is_ok() {
                before(db, &request, current.as_ref());
            }
            return Err(error);
        }
    };
    let edits = edits.map_err(|_| invalid_data_type())?;
    let value = match edits {
        ListEdits::Destinations(edits) => {
            let PropertyValue::ApplicationData(bytes) = &current else {
                unreachable!("list_target admits only framed destination lists")
            };
            // Decode BOTH lists before observation or mutation. A malformed
            // stored frame must not be treated as an empty list on removal.
            let mut destinations =
                decode_destination_list(bytes).map_err(|_| invalid_data_type())?;
            before(db, &request, Some(&current));
            if remove {
                destinations.retain(|d| !edits.contains(d));
            } else {
                destinations.extend(edits);
            }
            let mut bytes = BytesMut::new();
            bacnet_encoding::constructed::encode_destination_list(&mut bytes, &destinations);
            PropertyValue::ApplicationData(bytes.to_vec())
        }
        ListEdits::Values(edits) => {
            before(db, &request, Some(&current));
            let PropertyValue::List(mut items) = current else {
                unreachable!("list_target admits only lists of values")
            };
            if remove {
                items.retain(|item| !edits.contains(item));
            } else {
                items.extend(edits);
            }
            PropertyValue::List(items)
        }
    };
    db.get_mut(&request.object_identifier)
        .expect("readable object")
        .write_property(
            request.property_identifier,
            request.property_array_index,
            value,
            None,
        )
        .map_err(|error| match error {
            // Preserve AddListElement's existing Clause 15.1 resource mapping.
            Error::Protocol { class, code }
                if !remove
                    && class == ErrorClass::RESOURCES.to_raw() as u32
                    && code == ErrorCode::NO_SPACE_TO_WRITE_PROPERTY.to_raw() as u32 =>
            {
                Error::Protocol {
                    class,
                    code: ErrorCode::NO_SPACE_TO_ADD_LIST_ELEMENT.to_raw() as u32,
                }
            }
            other => other,
        })
}

#[cfg(test)]
mod tests {
    use super::*;
    use bacnet_objects::multistate::MultiStateInputObject;
    use bacnet_objects::traits::BACnetObject;
    use bacnet_services::list_manipulation::ListElementRequest;
    use bacnet_types::enums::ObjectType;
    use bytes::BytesMut;

    fn request(oid: ObjectIdentifier, element: u8, array_index: Option<u32>) -> BytesMut {
        request_with_elements(oid, vec![0x21, element], array_index)
    }

    fn request_with_elements(
        oid: ObjectIdentifier,
        list_of_elements: Vec<u8>,
        array_index: Option<u32>,
    ) -> BytesMut {
        let mut encoded = BytesMut::new();
        // Raw ingress fixture: intentionally permits malformed/empty/index-zero requests.
        bacnet_encoding::primitives::encode_ctx_object_id(&mut encoded, 0, &oid);
        bacnet_encoding::primitives::encode_ctx_enumerated(
            &mut encoded,
            1,
            PropertyIdentifier::ALARM_VALUES.to_raw(),
        );
        if let Some(index) = array_index {
            bacnet_encoding::primitives::encode_ctx_unsigned(&mut encoded, 2, u64::from(index));
        }
        encoded.extend_from_slice(&[0x3e]);
        encoded.extend_from_slice(&list_of_elements);
        encoded.extend_from_slice(&[0x3f]);
        encoded
    }

    #[test]
    fn add_and_remove_list_element_mutate_msi_alarm_values() {
        let oid = ObjectIdentifier::new(ObjectType::MULTI_STATE_INPUT, 1).unwrap();
        let mut db = ObjectDatabase::new();
        db.add(Box::new(MultiStateInputObject::new(1, "MSI-1", 3).unwrap()))
            .unwrap();

        handle_add_list_element(&mut db, &request(oid, 2, None)).unwrap();
        assert_eq!(
            db.get(&oid)
                .unwrap()
                .read_property(PropertyIdentifier::ALARM_VALUES, None)
                .unwrap(),
            PropertyValue::List(vec![PropertyValue::Unsigned(2)])
        );

        handle_remove_list_element(&mut db, &request(oid, 2, None)).unwrap();
        assert_eq!(
            db.get(&oid)
                .unwrap()
                .read_property(PropertyIdentifier::ALARM_VALUES, None)
                .unwrap(),
            PropertyValue::List(vec![])
        );
    }

    #[test]
    fn add_list_element_malformed_tail_errors_without_partial_commit() {
        let oid = ObjectIdentifier::new(ObjectType::MULTI_STATE_INPUT, 1).unwrap();
        let mut msi = MultiStateInputObject::new(1, "MSI-1", 3).unwrap();
        msi.set_alarm_values(vec![1]);
        let mut db = ObjectDatabase::new();
        db.add(Box::new(msi)).unwrap();

        let encoded = request_with_elements(oid, vec![0x21, 2, 0xD1, 0], None);
        match handle_add_list_element(&mut db, &encoded).unwrap_err() {
            Error::Protocol { class, code } => {
                assert_eq!(class, ErrorClass::PROPERTY.to_raw() as u32);
                assert_eq!(code, ErrorCode::INVALID_DATA_TYPE.to_raw() as u32);
            }
            other => panic!("expected PROPERTY/INVALID_DATA_TYPE, got {other:?}"),
        }
        assert_eq!(
            db.get(&oid)
                .unwrap()
                .read_property(PropertyIdentifier::ALARM_VALUES, None)
                .unwrap(),
            PropertyValue::List(vec![PropertyValue::Unsigned(1)])
        );
    }

    #[test]
    fn remove_list_element_malformed_tail_errors_without_partial_commit() {
        let oid = ObjectIdentifier::new(ObjectType::MULTI_STATE_INPUT, 1).unwrap();
        let mut msi = MultiStateInputObject::new(1, "MSI-1", 3).unwrap();
        msi.set_alarm_values(vec![2, 3]);
        let mut db = ObjectDatabase::new();
        db.add(Box::new(msi)).unwrap();

        let encoded = request_with_elements(oid, vec![0x21, 2, 0xD1, 0], None);
        match handle_remove_list_element(&mut db, &encoded).unwrap_err() {
            Error::Protocol { class, code } => {
                assert_eq!(class, ErrorClass::PROPERTY.to_raw() as u32);
                assert_eq!(code, ErrorCode::INVALID_DATA_TYPE.to_raw() as u32);
            }
            other => panic!("expected PROPERTY/INVALID_DATA_TYPE, got {other:?}"),
        }
        assert_eq!(
            db.get(&oid)
                .unwrap()
                .read_property(PropertyIdentifier::ALARM_VALUES, None)
                .unwrap(),
            PropertyValue::List(vec![PropertyValue::Unsigned(2), PropertyValue::Unsigned(3)])
        );
    }

    #[test]
    fn add_list_element_over_cap_returns_the_clause_15_1_error() {
        let oid = ObjectIdentifier::new(ObjectType::MULTI_STATE_INPUT, 1).unwrap();
        let mut msi = MultiStateInputObject::new(1, "MSI-1", 3).unwrap();
        // Fill to MAX_ALARM_VALUES (1024) so the appended element trips the cap.
        msi.set_alarm_values((0..1024).collect());
        let mut db = ObjectDatabase::new();
        db.add(Box::new(msi)).unwrap();

        let err = handle_add_list_element(&mut db, &request(oid, 7, None)).unwrap_err();
        match err {
            Error::Protocol { class, code } => {
                assert_eq!(class, ErrorClass::RESOURCES.to_raw() as u32);
                // Clause 15.1 names AddListElement's own error, not
                // WriteProperty's NO_SPACE_TO_WRITE_PROPERTY.
                assert_eq!(
                    code,
                    ErrorCode::NO_SPACE_TO_ADD_LIST_ELEMENT.to_raw() as u32
                );
            }
            other => panic!("expected Protocol error, got {other:?}"),
        }
        // The list must be unchanged.
        assert_eq!(
            db.get(&oid)
                .unwrap()
                .read_property(PropertyIdentifier::ALARM_VALUES, None)
                .unwrap(),
            PropertyValue::List((0..1024).map(PropertyValue::Unsigned).collect())
        );
    }

    #[test]
    fn add_list_element_rejects_array_index_on_alarm_values() {
        let oid = ObjectIdentifier::new(ObjectType::MULTI_STATE_INPUT, 1).unwrap();
        let mut db = ObjectDatabase::new();
        db.add(Box::new(MultiStateInputObject::new(1, "MSI-1", 3).unwrap()))
            .unwrap();

        match handle_add_list_element(&mut db, &request(oid, 2, Some(1))).unwrap_err() {
            Error::Protocol { class, code } => {
                assert_eq!(class, ErrorClass::PROPERTY.to_raw() as u32);
                assert_eq!(code, ErrorCode::PROPERTY_IS_NOT_AN_ARRAY.to_raw() as u32);
            }
            other => panic!("expected PROPERTY_IS_NOT_AN_ARRAY, got {other:?}"),
        }
        assert_eq!(
            db.get(&oid)
                .unwrap()
                .read_property(PropertyIdentifier::ALARM_VALUES, None)
                .unwrap(),
            PropertyValue::List(vec![])
        );
    }

    // ---- Framed Recipient_List element editing (#152 review) ----

    use bacnet_objects::notification_class::NotificationClass;
    use bacnet_types::bitstring::{DaysOfWeek, EventTransitionBits};
    use bacnet_types::constructed::{BACnetDestination, BACnetRecipient};
    use bacnet_types::primitives::Time;

    fn framed_dest(device_instance: u32) -> BACnetDestination {
        let t = |h, m| Time {
            hour: h,
            minute: m,
            second: 0,
            hundredths: 0,
        };
        BACnetDestination {
            valid_days: DaysOfWeek::all(),
            from_time: t(0, 0),
            to_time: t(23, 59),
            recipient: BACnetRecipient::Device(
                ObjectIdentifier::new(ObjectType::DEVICE, device_instance).unwrap(),
            ),
            process_identifier: device_instance,
            issue_confirmed_notifications: false,
            transitions: EventTransitionBits::all(),
        }
    }

    fn framed_bytes(destinations: &[BACnetDestination]) -> Vec<u8> {
        let mut buf = BytesMut::new();
        bacnet_encoding::constructed::encode_destination_list(&mut buf, destinations);
        buf.to_vec()
    }

    fn nc_db(entries: &[BACnetDestination]) -> (ObjectDatabase, ObjectIdentifier) {
        let mut db = ObjectDatabase::new();
        let mut nc = NotificationClass::new(1, "NC-1").unwrap();
        for d in entries {
            nc.add_destination(d.clone());
        }
        let oid = nc.object_identifier();
        db.add(Box::new(nc)).unwrap();
        (db, oid)
    }

    fn recipient_list_wire_bytes(db: &ObjectDatabase, oid: ObjectIdentifier) -> Vec<u8> {
        let v = db
            .get(&oid)
            .unwrap()
            .read_property(PropertyIdentifier::RECIPIENT_LIST, None)
            .unwrap();
        let PropertyValue::ApplicationData(bytes) = v else {
            panic!("expected ApplicationData");
        };
        bytes
    }

    fn device_instances(db: &ObjectDatabase, oid: ObjectIdentifier) -> Vec<u32> {
        let bytes = recipient_list_wire_bytes(db, oid);
        bacnet_encoding::constructed::decode_destination_list(&bytes)
            .unwrap()
            .iter()
            .map(|d| match &d.recipient {
                BACnetRecipient::Device(o) => o.instance_number(),
                other => panic!("expected Device recipient, got {other:?}"),
            })
            .collect()
    }

    #[test]
    fn remove_list_element_from_framed_recipient_list_leaves_rest() {
        let (mut db, oid) = nc_db(&[framed_dest(10), framed_dest(20), framed_dest(30)]);
        let request = ListElementRequest {
            object_identifier: oid,
            property_identifier: PropertyIdentifier::RECIPIENT_LIST,
            property_array_index: None,
            list_of_elements: framed_bytes(&[framed_dest(20)]),
        };
        let mut buf = BytesMut::new();
        request.encode(&mut buf).unwrap();
        handle_remove_list_element(&mut db, &buf).unwrap();
        assert_eq!(device_instances(&db, oid), vec![10, 30]);
        // The wire form re-encodes as exactly the two remaining destinations.
        assert_eq!(
            recipient_list_wire_bytes(&db, oid),
            framed_bytes(&[framed_dest(10), framed_dest(30)])
        );
    }

    #[test]
    fn remove_list_element_non_matching_entry_is_noop() {
        let (mut db, oid) = nc_db(&[framed_dest(10), framed_dest(20)]);
        let before = recipient_list_wire_bytes(&db, oid);
        let request = ListElementRequest {
            object_identifier: oid,
            property_identifier: PropertyIdentifier::RECIPIENT_LIST,
            property_array_index: None,
            list_of_elements: framed_bytes(&[framed_dest(99)]),
        };
        let mut buf = BytesMut::new();
        request.encode(&mut buf).unwrap();
        handle_remove_list_element(&mut db, &buf).unwrap();
        assert_eq!(device_instances(&db, oid), vec![10, 20]);
        assert_eq!(
            recipient_list_wire_bytes(&db, oid),
            before,
            "bytes unchanged"
        );
    }

    #[test]
    fn add_list_element_to_framed_recipient_list_appends() {
        let (mut db, oid) = nc_db(&[framed_dest(10)]);
        let request = ListElementRequest {
            object_identifier: oid,
            property_identifier: PropertyIdentifier::RECIPIENT_LIST,
            property_array_index: None,
            list_of_elements: framed_bytes(&[framed_dest(20), framed_dest(30)]),
        };
        let mut buf = BytesMut::new();
        request.encode(&mut buf).unwrap();
        handle_add_list_element(&mut db, &buf).unwrap();
        assert_eq!(device_instances(&db, oid), vec![10, 20, 30]);
        assert_eq!(
            recipient_list_wire_bytes(&db, oid),
            framed_bytes(&[framed_dest(10), framed_dest(20), framed_dest(30)])
        );
    }

    #[test]
    fn remove_list_element_malformed_framed_payload_errors_and_preserves() {
        let (mut db, oid) = nc_db(&[framed_dest(10), framed_dest(20)]);
        let before = recipient_list_wire_bytes(&db, oid);
        // Well-formed TLV, but NOT a BACnetDestination (a bare application
        // Unsigned where the destination's valid-days bit string belongs).
        let request = ListElementRequest {
            object_identifier: oid,
            property_identifier: PropertyIdentifier::RECIPIENT_LIST,
            property_array_index: None,
            list_of_elements: vec![0x21, 0x2A],
        };
        let mut buf = BytesMut::new();
        request.encode(&mut buf).unwrap();
        let err = handle_remove_list_element(&mut db, &buf).unwrap_err();
        match err {
            Error::Protocol { class, code } => {
                assert_eq!(class, ErrorClass::PROPERTY.to_raw() as u32);
                assert_eq!(code, ErrorCode::INVALID_DATA_TYPE.to_raw() as u32);
            }
            other => panic!("expected PROPERTY/INVALID_DATA_TYPE, got {other:?}"),
        }
        assert_eq!(
            recipient_list_wire_bytes(&db, oid),
            before,
            "no silent wipe"
        );
    }

    #[test]
    fn whole_list_write_property_decodes_all_elements() {
        let oid = ObjectIdentifier::new(ObjectType::MULTI_STATE_INPUT, 1).unwrap();
        let mut db = ObjectDatabase::new();
        db.add(Box::new(MultiStateInputObject::new(1, "MSI-1", 3).unwrap()))
            .unwrap();
        let request = WritePropertyRequest {
            object_identifier: oid,
            property_identifier: PropertyIdentifier::ALARM_VALUES,
            property_array_index: None,
            // A BACnetLIST is consecutive application-tagged elements.
            property_value: vec![0x21, 2, 0x21, 3],
            priority: None,
        };
        let mut encoded = BytesMut::new();
        request.encode(&mut encoded).unwrap();

        // #182: WriteProperty loop-decodes the whole payload, so the
        // whole-list write lands with per-element validation in the arm.
        handle_write_property(&mut db, &encoded).unwrap();
        assert_eq!(
            db.get(&oid)
                .unwrap()
                .read_property(PropertyIdentifier::ALARM_VALUES, None)
                .unwrap(),
            PropertyValue::List(vec![PropertyValue::Unsigned(2), PropertyValue::Unsigned(3)])
        );

        // Per-element validation still applies: one non-Unsigned member
        // refuses the whole write and leaves the list untouched.
        let request = WritePropertyRequest {
            object_identifier: oid,
            property_identifier: PropertyIdentifier::ALARM_VALUES,
            property_array_index: None,
            property_value: vec![0x21, 4, 0x11], // Unsigned 4, Boolean true
            priority: None,
        };
        let mut encoded = BytesMut::new();
        request.encode(&mut encoded).unwrap();
        match handle_write_property(&mut db, &encoded).unwrap_err() {
            Error::Protocol { class, code } => {
                assert_eq!(class, ErrorClass::PROPERTY.to_raw() as u32);
                assert_eq!(code, ErrorCode::INVALID_DATA_TYPE.to_raw() as u32);
            }
            other => panic!("expected INVALID_DATA_TYPE, got {other:?}"),
        }
        assert_eq!(
            db.get(&oid)
                .unwrap()
                .read_property(PropertyIdentifier::ALARM_VALUES, None)
                .unwrap(),
            PropertyValue::List(vec![PropertyValue::Unsigned(2), PropertyValue::Unsigned(3)]),
            "refused write leaves the list unchanged"
        );
    }
}
