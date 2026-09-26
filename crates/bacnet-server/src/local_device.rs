use bacnet_objects::database::ObjectDatabase;
use bacnet_types::enums::ObjectType;
use bacnet_types::primitives::ObjectIdentifier;

/// Select the lowest Device instance for wildcard reads, discovery and notifications.
///
/// Clause 12.11 expects one Device per BACnet device. For a database with
/// several Devices this is a deterministic local policy, independent of hash
/// or insertion order. Concrete instances precede the maximum wildcard; a
/// wildcard-only database retains its existing selection. No Device yields
/// `None`, leaving each caller's existing fallback intact.
///
/// Selection uses the current database guard. Changing Device membership after
/// startup does not rebind the discovery limiter's startup identity.
pub(crate) fn selected_device(db: &ObjectDatabase) -> Option<ObjectIdentifier> {
    select_device(db.find_by_type(ObjectType::DEVICE))
}

fn select_device(
    candidates: impl IntoIterator<Item = ObjectIdentifier>,
) -> Option<ObjectIdentifier> {
    candidates
        .into_iter()
        .filter(|candidate| candidate.object_type() == ObjectType::DEVICE)
        .min_by_key(|candidate| candidate.instance_number())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn selected_device_is_independent_of_iteration_order() {
        let low = ObjectIdentifier::new(ObjectType::DEVICE, 813).unwrap();
        let high = ObjectIdentifier::new(ObjectType::DEVICE, 900).unwrap();
        let wildcard = ObjectIdentifier::new(ObjectType::DEVICE, 4194303).unwrap();
        let analog = ObjectIdentifier::new(ObjectType::ANALOG_VALUE, 1).unwrap();
        for candidates in [
            [analog, high, low, wildcard],
            [analog, low, high, wildcard],
            [wildcard, high, low, analog],
        ] {
            assert_eq!(select_device(candidates), Some(low));
        }
    }

    #[test]
    fn selected_device_preserves_empty_single_and_wildcard_only_cases() {
        let device = ObjectIdentifier::new(ObjectType::DEVICE, 813).unwrap();
        let wildcard = ObjectIdentifier::new(ObjectType::DEVICE, 4194303).unwrap();
        let analog = ObjectIdentifier::new(ObjectType::ANALOG_VALUE, 1).unwrap();
        assert_eq!(select_device([]), None);
        assert_eq!(select_device([analog]), None);
        assert_eq!(select_device([analog, device]), Some(device));
        assert_eq!(select_device([analog, wildcard]), Some(wildcard));
    }
}
