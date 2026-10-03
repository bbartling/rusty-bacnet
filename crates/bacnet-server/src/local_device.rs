use bacnet_objects::database::ObjectDatabase;
use bacnet_types::primitives::ObjectIdentifier;

/// Validate the current [selected Device](ObjectDatabase::selected_device)
/// under the caller's database guard.
/// An empty database remains supported; applications own their Device objects.
pub(crate) fn validate_apdu_declaration(
    db: &ObjectDatabase,
    capacity: u32,
) -> Result<Option<ObjectIdentifier>, bacnet_types::error::Error> {
    use bacnet_types::primitives::PropertyValue;
    use bacnet_types::{enums::PropertyIdentifier, error::Error};
    let Some(oid) = db.selected_device() else {
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
