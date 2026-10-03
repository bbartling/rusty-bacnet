use bacnet_objects::database::ObjectDatabase;
use bacnet_types::primitives::ObjectIdentifier;

/// The Device this server answers for in wildcard reads, discovery and
/// notifications: [`ObjectDatabase::selected_device`], which owns the policy
/// for a database with several Devices.
///
/// Selection uses the current database guard. Changing Device membership after
/// startup does not rebind the discovery limiter's startup identity.
pub(crate) fn selected_device(db: &ObjectDatabase) -> Option<ObjectIdentifier> {
    db.selected_device()
}

/// Validate the current selected Device under the caller's database guard.
/// An empty database remains supported; applications own their Device objects.
pub(crate) fn validate_apdu_declaration(
    db: &ObjectDatabase,
    capacity: u32,
) -> Result<Option<ObjectIdentifier>, bacnet_types::error::Error> {
    use bacnet_types::primitives::PropertyValue;
    use bacnet_types::{enums::PropertyIdentifier, error::Error};
    let Some(oid) = selected_device(db) else {
        return Ok(None);
    };
    let declared = db
        .get(&oid)
        .expect("selected under same database guard")
        .read_property(PropertyIdentifier::MAX_APDU_LENGTH_ACCEPTED, None)?;
    if declared != PropertyValue::Unsigned(u64::from(capacity)) {
        return Err(Error::Encoding(format!(
            "selected Device Max_APDU_Length_Accepted must equal effective server capacity {capacity}"
        )));
    }
    Ok(Some(oid))
}
