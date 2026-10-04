//! Registration of the Access Rights object with its Positive_Access_Rules
//! and Negative_Access_Rules (#1316) and its Enable flag (#1332). Peers can
//! write all three over the network too (#1330); these keyword arguments
//! set what the object starts with, and `storage_path` keeps what peers
//! write across a restart (#1392).
use super::super::*;
use bacnet_objects::access_control::FileAccessRightsPersistence;
use bacnet_types::constructed::BACnetAccessRule;
use bacnet_types::error::Error;

#[pymethods]
impl BACnetServer {
    /// Add an Access Rights object to the server (before starting).
    ///
    /// `positive_access_rules` and `negative_access_rules` set the two rule
    /// arrays as lists of `AccessRule` mappings. A rule's `enable` (a bool)
    /// is required. Its `time_range`, when given, names the property that
    /// decides when the rule applies, as a mapping of `object_identifier`,
    /// `property_identifier` and the optional `property_array_index` and
    /// `device_identifier`; left out or `None`, the rule applies at any time.
    /// Its `location`, when given, limits it to one Access Point or one
    /// Access Zone, as an `ObjectIdentifier` or a `(device, object)` pair;
    /// left out or `None`, it covers every access point.
    ///
    /// `enable` sets the object's Enable flag (property 133, `LOG_ENABLE`),
    /// TRUE when omitted; FALSE disables every rule in both arrays.
    ///
    /// With `storage_path` (a `str`), a rule array or Enable that a client
    /// writes is kept in that file and restored when the server is built
    /// again. It then wins over the keyword given here, which is checked but
    /// not applied. A write that cannot be saved is refused with DEVICE /
    /// OPERATIONAL_PROBLEM, and the old value stays. Without it, writes live
    /// in memory only. Give each object its own file: one that holds another
    /// object's state, or that this backend did not write, raises
    /// BacnetError here, and one holding a rule the object refuses raises
    /// BacnetProtocolError.
    ///
    /// A wrong shape or type raises TypeError, an unknown or missing key or a
    /// device that isn't a Device raises ValueError, and a location naming
    /// another object type raises a protocol error (VALUE_OUT_OF_RANGE), as
    /// does a list of more than 1024 rules (NO_SPACE_TO_WRITE_PROPERTY).
    /// Nothing is registered after any of them.
    #[pyo3(signature = (
        instance,
        name,
        *,
        positive_access_rules=None,
        negative_access_rules=None,
        enable=true,
        storage_path=None,
    ))]
    fn add_access_rights(
        &self,
        instance: u32,
        name: &str,
        positive_access_rules: Option<Bound<'_, PyAny>>,
        negative_access_rules: Option<Bound<'_, PyAny>>,
        enable: bool,
        storage_path: Option<&str>,
    ) -> PyResult<()> {
        let rules = |rules: Option<Bound<'_, PyAny>>, keyword: &str| {
            rules
                .map(|rules| crate::types::access_rules_from_py(&rules, keyword))
                .transpose()
        };
        let positive = rules(positive_access_rules, "positive_access_rules")?;
        let negative = rules(negative_access_rules, "negative_access_rules")?;
        let obj = access_rights(instance, name, storage_path, positive, negative, enable)
            .map_err(to_py_err)?;
        self.push_pending(Box::new(obj))
    }
}

/// Build an Access Rights object, kept in the file at `storage_path` when
/// one is given, then apply each rule array given through its validating
/// setter, and the Enable flag. A value storage holds from a write wins over
/// the one given here.
fn access_rights(
    instance: u32,
    name: &str,
    storage_path: Option<&str>,
    positive: Option<Vec<BACnetAccessRule>>,
    negative: Option<Vec<BACnetAccessRule>>,
    enable: bool,
) -> Result<AccessRightsObject, Error> {
    let mut obj = match storage_path {
        Some(path) => {
            let storage = Arc::new(FileAccessRightsPersistence::new(path)?);
            AccessRightsObject::with_persistence(instance, name, storage)?
        }
        None => AccessRightsObject::new(instance, name)?,
    };
    if let Some(rules) = positive {
        obj.set_positive_access_rules(rules)?;
    }
    if let Some(rules) = negative {
        obj.set_negative_access_rules(rules)?;
    }
    obj.set_enable(enable);
    Ok(obj)
}

#[cfg(test)]
#[path = "access_rights_methods_tests.rs"]
mod tests;
