//! A Group object's Present_Value, rebuilt from its members on every read
//! (Clause 12.14.6).
//!
//! A Group stores no Present_Value: the object can't reach its members, so
//! the read services build the list here, under the database guard the
//! request already holds.
//!
//! Work policy (#1172): a Group may list any number of members, and the
//! request that reads its Present_Value pays for them. Each member row, after
//! ALL, REQUIRED and OPTIONAL expand, counts against the same work limit as
//! the request's own rows (`ReadPropertyMultipleBudget::max_result_elements`).
//! Several Groups in one ReadPropertyMultiple share that one limit, and a
//! request that would pass it is aborted with OUT_OF_RESOURCES before any
//! member is read, the answer ReadPropertyMultiple gives any request over its
//! work limit. ReadProperty and ReadRange have no work limit of their own, so
//! they get the limit of a ReadPropertyMultiple that names only this
//! Present_Value: the row itself plus the member rows. The low-level helpers
//! with no executor view have no limit.
//!
//! A member may name the Device's COV subscription lists. The request
//! pre-scan (`active_cov_device`, `active_cov_device_for_rpm`) looks through
//! the members of every Group whose Present_Value a request may read, so those
//! rows serve the request's one live snapshot (#1171).
use super::rpm_budget::{self, PlannedObject, RpmFailure, Work};
use super::*;
use bacnet_encoding::constructed::decode_read_access_specification;
use bacnet_objects::traits::BACnetObject;
use bacnet_types::constructed::{PropertyReference, ReadAccessSpecification};

/// A Group's members, planned for the request that reads its Present_Value.
/// A list that doesn't decode keeps its error for the row to report.
pub(super) struct GroupMembers(Result<Vec<PlannedObject>, Error>);

/// Read `property` of a found object the way the single-property services
/// (ReadProperty, ReadRange) serve it. A Group's whole Present_Value is
/// rebuilt from its members, charged with the read's own row to the view's
/// work limit; every other read is the object's own answer (the executor's,
/// when `object` is a served view).
pub(super) fn read_served_property(
    db: &ObjectDatabase,
    view: Option<&DeviceReadContext<'_>>,
    object: &dyn BACnetObject,
    property: PropertyIdentifier,
    array_index: Option<u32>,
) -> Result<PropertyValue, RpmFailure> {
    let reference = PropertyReference {
        property_identifier: property,
        property_array_index: array_index,
    };
    let mut work = Work::new(view.map_or(usize::MAX, |view| view.work_limit));
    // This read's own row, as a one-property ReadPropertyMultiple counts it.
    work.charge()?;
    match plan_members(db, view, object, &reference, &mut work)? {
        Some(members) => value(db, view, members),
        None => object.read_property(property, array_index),
    }
    .map_err(RpmFailure::Service)
}

/// The members, when `reference` reads the whole Present_Value of `object`
/// and `object` is a Group; `None` for any other row. Each member is planned
/// as ReadPropertyMultiple plans one specification, and every member row is
/// charged to `work`.
pub(super) fn plan_members(
    db: &ObjectDatabase,
    view: Option<&DeviceReadContext<'_>>,
    object: &dyn BACnetObject,
    reference: &PropertyReference,
    work: &mut Work,
) -> Result<Option<GroupMembers>, RpmFailure> {
    if reference.property_identifier != PropertyIdentifier::PRESENT_VALUE
        || reference.property_array_index.is_some()
        || object.object_identifier().object_type() != ObjectType::GROUP
    {
        return Ok(None);
    }
    let planned = match members(object) {
        Ok(specs) => Ok(rpm_budget::plan_specs(db, &specs, work, view, false)?),
        Err(error) => Err(error),
    };
    Ok(Some(GroupMembers(planned)))
}

/// One ReadAccessResult per member, in List_Of_Group_Members order.
///
/// Each member is read as ReadPropertyMultiple reads one specification:
/// ALL, REQUIRED and OPTIONAL expand against the member, a member naming no
/// object in this device gets OBJECT / UNKNOWN_OBJECT for each reference,
/// and a property that fails to read carries its error in place of a value.
/// Member rows were planned without Group expansion, so they use each
/// object's own reader and a Group listed as a member can't make this read
/// recurse.
pub(super) fn value(
    db: &ObjectDatabase,
    view: Option<&DeviceReadContext<'_>>,
    members: GroupMembers,
) -> Result<PropertyValue, Error> {
    let results = members
        .0?
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
                    .into_iter()
                    .map(|row| rpm_budget::read_row(db, view, object, row))
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
pub(super) fn members(group: &dyn BACnetObject) -> Result<Vec<ReadAccessSpecification>, Error> {
    let PropertyValue::List(elements) =
        group.read_property(PropertyIdentifier::LIST_OF_GROUP_MEMBERS, None)?
    else {
        return Err(other());
    };
    elements
        .iter()
        .map(|element| match element {
            PropertyValue::ApplicationData(bytes) => {
                match decode_read_access_specification(bytes, 0) {
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
