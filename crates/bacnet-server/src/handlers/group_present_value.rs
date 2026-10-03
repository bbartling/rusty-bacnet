//! A Group object's Present_Value, rebuilt from its members on every read
//! (Clause 12.14.6).
//!
//! A Group stores no Present_Value: the object can't reach its members, so
//! the read services build the list here, under the database guard the
//! request already holds.
use super::rpm_budget;
use super::*;
use bacnet_objects::traits::BACnetObject;
use bacnet_services::rpm::ReadAccessSpecification;

/// Read `property` of a found object the way the read services serve it.
/// A Group's whole Present_Value is rebuilt from its members; every other
/// read is the object's own answer (the executor's, when `object` is a
/// served view).
pub(super) fn read_served_property(
    db: &ObjectDatabase,
    view: Option<&DeviceReadContext<'_>>,
    object: &dyn BACnetObject,
    property: PropertyIdentifier,
    array_index: Option<u32>,
) -> Result<PropertyValue, Error> {
    if property == PropertyIdentifier::PRESENT_VALUE
        && array_index.is_none()
        && object.object_identifier().object_type() == ObjectType::GROUP
    {
        return group_present_value(db, view, object);
    }
    object.read_property(property, array_index)
}

/// One ReadAccessResult per member, in List_Of_Group_Members order.
///
/// Each member is read as ReadPropertyMultiple reads one specification:
/// ALL, REQUIRED and OPTIONAL expand against the member, a member naming no
/// object in this device gets OBJECT / UNKNOWN_OBJECT for each reference,
/// and a property that fails to read carries its error in place of a value.
/// The member rows use the object's own reader, never
/// [`read_served_property`], so a Group listed as a member can't make this
/// read recurse.
fn group_present_value(
    db: &ObjectDatabase,
    view: Option<&DeviceReadContext<'_>>,
    group: &dyn BACnetObject,
) -> Result<PropertyValue, Error> {
    let request = ReadPropertyMultipleRequest {
        list_of_read_access_specs: members(group)?,
    };
    // The members are local configuration, read-only on the network, so
    // their expansion is not charged to any request budget.
    let plan = rpm_budget::plan(db, &request, usize::MAX, view).map_err(|_| other())?;
    let results = plan
        .into_iter()
        .map(|member| {
            let stored = read_property::read_target_object(db, &member.lookup_oid);
            let served = stored.and_then(|object| view.map(|view| view.object(object)));
            let object = served
                .as_ref()
                .map(|served| served as &dyn BACnetObject)
                .or(stored);
            let result = ReadAccessResult {
                object_identifier: member.lookup_oid,
                list_of_results: member
                    .properties
                    .iter()
                    .map(|reference| {
                        rpm_budget::element(object, reference, |object| {
                            object.read_property(
                                reference.property_identifier,
                                reference.property_array_index,
                            )
                        })
                    })
                    .collect(),
            };
            let mut encoded = BytesMut::new();
            result.encode(&mut encoded);
            PropertyValue::ApplicationData(encoded.to_vec())
        })
        .collect();
    Ok(PropertyValue::List(results))
}

/// The group's members, decoded from its List_Of_Group_Members elements.
/// A built-in Group always serves decodable ones; a custom object whose
/// list doesn't decode fails the read with PROPERTY / OTHER.
fn members(group: &dyn BACnetObject) -> Result<Vec<ReadAccessSpecification>, Error> {
    let PropertyValue::List(elements) =
        group.read_property(PropertyIdentifier::LIST_OF_GROUP_MEMBERS, None)?
    else {
        return Err(other());
    };
    elements
        .iter()
        .map(|element| match element {
            PropertyValue::ApplicationData(bytes) => {
                match ReadAccessSpecification::decode(bytes, 0) {
                    Ok((member, end)) if end == bytes.len() => Ok(member),
                    _ => Err(other()),
                }
            }
            _ => Err(other()),
        })
        .collect()
}

fn other() -> Error {
    Error::Protocol {
        class: ErrorClass::PROPERTY.to_raw() as u32,
        code: ErrorCode::OTHER.to_raw() as u32,
    }
}
