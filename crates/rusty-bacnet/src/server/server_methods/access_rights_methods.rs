//! Registration of the Access Rights object with its Positive_Access_Rules
//! and Negative_Access_Rules (#1316). Both arrays are read-only over the
//! network, so these keyword arguments are the Python route to them.
use super::super::*;
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
    /// A wrong shape or type raises TypeError, an unknown or missing key or a
    /// device that isn't a Device raises ValueError, and a location naming
    /// another object type raises a protocol error (VALUE_OUT_OF_RANGE).
    /// Nothing is registered after any of them.
    #[pyo3(signature = (instance, name, *, positive_access_rules=None, negative_access_rules=None))]
    fn add_access_rights(
        &self,
        instance: u32,
        name: &str,
        positive_access_rules: Option<Bound<'_, PyAny>>,
        negative_access_rules: Option<Bound<'_, PyAny>>,
    ) -> PyResult<()> {
        let rules = |rules: Option<Bound<'_, PyAny>>, keyword: &str| {
            rules
                .map(|rules| crate::types::access_rules_from_py(&rules, keyword))
                .transpose()
        };
        let positive = rules(positive_access_rules, "positive_access_rules")?;
        let negative = rules(negative_access_rules, "negative_access_rules")?;
        let obj = access_rights(instance, name, positive, negative).map_err(to_py_err)?;
        self.push_pending(Box::new(obj))
    }
}

/// Build an Access Rights object, applying each rule array given through
/// its validating setter.
fn access_rights(
    instance: u32,
    name: &str,
    positive: Option<Vec<BACnetAccessRule>>,
    negative: Option<Vec<BACnetAccessRule>>,
) -> Result<AccessRightsObject, Error> {
    let mut obj = AccessRightsObject::new(instance, name)?;
    if let Some(rules) = positive {
        obj.set_positive_access_rules(rules)?;
    }
    if let Some(rules) = negative {
        obj.set_negative_access_rules(rules)?;
    }
    Ok(obj)
}

#[cfg(test)]
#[path = "access_rights_methods_tests.rs"]
mod tests;
