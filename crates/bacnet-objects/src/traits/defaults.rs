use bacnet_types::enums::{ObjectType, PropertyIdentifier};

use super::CovReportedProperty;

/// The Table 13-1 properties a whole-object COV notification carries after
/// its leading value and Status_Flags, behind
/// [`super::BACnetObject::cov_reported_properties`]. A free function for the
/// same `dyn` reason as [`array_property_default`].
///
/// Every row Table 13-1 gives more than Present_Value and Status_Flags is
/// here. Access Point's row leads with Access_Event instead of Present_Value;
/// the server supplies that leading value, so only the rest is listed.
pub(super) fn cov_reported_properties_default(
    object_type: ObjectType,
) -> &'static [CovReportedProperty] {
    use CovReportedProperty::{Trigger, Value};
    use PropertyIdentifier as P;
    match object_type {
        ObjectType::ACCESS_DOOR => &[Trigger(P::DOOR_ALARM_STATE)],
        ObjectType::ACCESS_POINT => &[
            Value(P::ACCESS_EVENT_TAG),
            Trigger(P::ACCESS_EVENT_TIME),
            Value(P::ACCESS_EVENT_CREDENTIAL),
            Value(P::ACCESS_EVENT_AUTHENTICATION_FACTOR),
        ],
        ObjectType::CREDENTIAL_DATA_INPUT => &[Trigger(P::UPDATE_TIME)],
        ObjectType::LOAD_CONTROL => &[
            Trigger(P::REQUESTED_SHED_LEVEL),
            Trigger(P::START_TIME),
            Trigger(P::SHED_DURATION),
            Trigger(P::DUTY_WINDOW),
        ],
        ObjectType::LOOP => &[Value(P::SETPOINT), Value(P::CONTROLLED_VARIABLE_VALUE)],
        ObjectType::PULSE_CONVERTER => &[Value(P::UPDATE_TIME)],
        ObjectType::STAGING => &[Trigger(P::PRESENT_STAGE)],
        _ => &[],
    }
}

/// The default array/list classification behind
/// [`super::BACnetObject::is_array_property`], keyed by the Clause 12 property
/// tables. Three identifier classes:
///
/// - **Identifier-stable BACnetARRAY** properties admit an index on every
///   object type that defines them: OBJECT_LIST (Table 12-13), PROPERTY_LIST
///   (every table), STATE_TEXT (Tables 12-21/12-22/12-23), PRIORITY
///   (Table 12-24), WEEKLY_SCHEDULE / EXCEPTION_SCHEDULE (Table 12-28),
///   EVENT_TIME_STAMPS / EVENT_MESSAGE_TEXTS (Table 12-2 family),
///   PRIORITY_ARRAY (the commandable family), TAGS (Annex Y),
///   SUBORDINATE_LIST / SUBORDINATE_ANNOTATIONS (Table 12-34),
///   GROUP_MEMBERS / GROUP_MEMBER_NAMES (Table 12-57; Elevator/Lift also type
///   GROUP_MEMBERS BACnetARRAY), STAGES / STAGE_NAMES / TARGET_REFERENCES
///   (Table 12-80), MONITORED_OBJECTS (Table 12-82), and
///   AUTHENTICATION_FACTORS / ASSIGNED_ACCESS_RIGHTS (Table 12-40, the only
///   table carrying either).
/// - **Type-dependent** identifiers classify by `object_type`: ACTION is
///   BACnetARRAY[N] on Command (Table 12-12) but a single BACnetAction on Loop
///   (Table 12-20), and ACTION_TEXT, its parallel array of descriptions, is
///   classified on Command, the only type that has it; ALARM_VALUES / FAULT_VALUES are BACnetARRAY[N] on
///   CharacterString Value (Table 12-44) and BitString Value (Table 12-47) but
///   BACnetLIST on the multi-state, life-safety, and access families;
///   LIST_OF_OBJECT_PROPERTY_REFERENCES is
///   BACnetARRAY[N] on Channel (Table 12-62) but BACnetLIST on Schedule
///   (Table 12-28) and Timer (Table 12-75); PRESENT_VALUE is
///   BACnetARRAY[N] of BACnetPropertyAccessResult on Global Group
///   (Table 12-57) but scalar elsewhere.
/// - **Everything else** — scalars and the identifier-stable BACnetLIST
///   properties DATE_LIST (Table 12-11), LIST_OF_GROUP_MEMBERS
///   (Table 12-17), RECIPIENT_LIST (Table 12-24), LOG_BUFFER
///   (Tables 12-29/12-31), DEVICE_ADDRESS_BINDING and
///   ACTIVE_COV_SUBSCRIPTIONS (Table 12-13) — takes no index: Clause 12.1.5.2
///   makes ReadRange the only positional access to a BACnetLIST. Array-typed
///   identifiers whose object types are not modeled in-tree (e.g.
///   EVENT_MESSAGE_TEXTS_CONFIG) stay
///   rejected until their object-side modeling lands.
///
/// Like [`historical_writable_default`] this is a free function (not a
/// per-object override) so the default trait method can delegate to it
/// without requiring `Self: Sized` (which would break `dyn BACnetObject`
/// dispatch).
#[inline]
pub(super) fn array_property_default(
    object_type: ObjectType,
    property: PropertyIdentifier,
) -> bool {
    match property {
        PropertyIdentifier::OBJECT_LIST
        | PropertyIdentifier::PROPERTY_LIST
        | PropertyIdentifier::STATE_TEXT
        | PropertyIdentifier::PRIORITY
        | PropertyIdentifier::WEEKLY_SCHEDULE
        | PropertyIdentifier::EXCEPTION_SCHEDULE
        | PropertyIdentifier::EVENT_TIME_STAMPS
        | PropertyIdentifier::EVENT_MESSAGE_TEXTS
        | PropertyIdentifier::PRIORITY_ARRAY
        | PropertyIdentifier::TAGS
        | PropertyIdentifier::SUBORDINATE_LIST
        | PropertyIdentifier::SUBORDINATE_ANNOTATIONS
        | PropertyIdentifier::GROUP_MEMBERS
        | PropertyIdentifier::GROUP_MEMBER_NAMES
        | PropertyIdentifier::STAGES
        | PropertyIdentifier::STAGE_NAMES
        | PropertyIdentifier::MONITORED_OBJECTS
        | PropertyIdentifier::TARGET_REFERENCES
        | PropertyIdentifier::AUTHENTICATION_FACTORS
        | PropertyIdentifier::ASSIGNED_ACCESS_RIGHTS => true,
        PropertyIdentifier::ACTION | PropertyIdentifier::ACTION_TEXT => {
            object_type == ObjectType::COMMAND
        }
        PropertyIdentifier::ALARM_VALUES | PropertyIdentifier::FAULT_VALUES => matches!(
            object_type,
            ObjectType::CHARACTERSTRING_VALUE | ObjectType::BITSTRING_VALUE
        ),
        PropertyIdentifier::LIST_OF_OBJECT_PROPERTY_REFERENCES => {
            object_type == ObjectType::CHANNEL
        }
        PropertyIdentifier::VALUE_SOURCE_ARRAY => matches!(
            object_type,
            ObjectType::ANALOG_OUTPUT
                | ObjectType::ANALOG_VALUE
                | ObjectType::BINARY_OUTPUT
                | ObjectType::BINARY_VALUE
                | ObjectType::MULTI_STATE_OUTPUT
                | ObjectType::MULTI_STATE_VALUE
        ),
        PropertyIdentifier::PRESENT_VALUE => object_type == ObjectType::GLOBAL_GROUP,
        _ => false,
    }
}

/// The default BACnetLIST classification behind
/// [`super::BACnetObject::is_list_property`], keyed by the property datatypes
/// in the Clause 12 object tables. Two identifier classes:
///
/// - **Identifier-stable BACnetLIST** properties are lists on every object
///   type that defines them: DATE_LIST (Table 12-11); the Device lists of
///   Table 12-13 (address bindings, the COV and COV-multiple subscriptions,
///   the VT classes and sessions, and the three recipient lists);
///   LIST_OF_GROUP_MEMBERS (Table 12-17); RECIPIENT_LIST (Tables 12-24 and
///   12-58); LOG_BUFFER (Tables 12-29, 12-31, 12-35 and 12-83); the
///   life-safety mode, alarm-value and zone-member lists (Tables 12-18 and
///   12-19); the access-control event, zone, user, credential and exemption
///   lists (Tables 12-30 and 12-36 to 12-40); COVU_RECIPIENTS (Table 12-57);
///   SUBSCRIBED_RECIPIENTS (Table 12-58); the B/IP, MS/TP and routing tables
///   of Network Port (Table 12-71); LANDING_CALLS (Table 12-76); and
///   FAULT_SIGNALS (Tables 12-77 and 12-78).
/// - **Type-dependent** identifiers classify by `object_type`: ALARM_VALUES /
///   FAULT_VALUES are lists except on CharacterString Value and BitString
///   Value, where they are arrays; LIST_OF_OBJECT_PROPERTY_REFERENCES is a list
///   except on Channel (an array); PRESENT_VALUE is a list only on Group
///   (Table 12-17); MEMBER_OF is a list on Life Safety Point, Life Safety Zone
///   and Access User but a single BACnetDeviceObjectReference on Audit Log.
///
/// Everything else is a scalar, a constructed single value or a BACnetARRAY.
/// The 2020 tables define no BACnetARRAY of BACnetLIST, so no identifier is
/// both an array and a list here.
#[inline]
pub(super) fn list_property_default(object_type: ObjectType, property: PropertyIdentifier) -> bool {
    match property {
        PropertyIdentifier::DATE_LIST
        | PropertyIdentifier::DEVICE_ADDRESS_BINDING
        | PropertyIdentifier::ACTIVE_COV_SUBSCRIPTIONS
        | PropertyIdentifier::ACTIVE_COV_MULTIPLE_SUBSCRIPTIONS
        | PropertyIdentifier::VT_CLASSES_SUPPORTED
        | PropertyIdentifier::ACTIVE_VT_SESSIONS
        | PropertyIdentifier::TIME_SYNCHRONIZATION_RECIPIENTS
        | PropertyIdentifier::UTC_TIME_SYNCHRONIZATION_RECIPIENTS
        | PropertyIdentifier::RESTART_NOTIFICATION_RECIPIENTS
        | PropertyIdentifier::LIST_OF_GROUP_MEMBERS
        | PropertyIdentifier::RECIPIENT_LIST
        | PropertyIdentifier::LOG_BUFFER
        | PropertyIdentifier::ACCEPTED_MODES
        | PropertyIdentifier::LIFE_SAFETY_ALARM_VALUES
        | PropertyIdentifier::ZONE_MEMBERS
        | PropertyIdentifier::MASKED_ALARM_VALUES
        | PropertyIdentifier::FAILED_ATTEMPT_EVENTS
        | PropertyIdentifier::ACCESS_ALARM_EVENTS
        | PropertyIdentifier::ACCESS_TRANSACTION_EVENTS
        | PropertyIdentifier::CREDENTIALS_IN_ZONE
        | PropertyIdentifier::ENTRY_POINTS
        | PropertyIdentifier::EXIT_POINTS
        | PropertyIdentifier::MEMBERS
        | PropertyIdentifier::CREDENTIALS
        | PropertyIdentifier::REASON_FOR_DISABLE
        | PropertyIdentifier::AUTHORIZATION_EXEMPTIONS
        | PropertyIdentifier::COVU_RECIPIENTS
        | PropertyIdentifier::SUBSCRIBED_RECIPIENTS
        | PropertyIdentifier::BBMD_BROADCAST_DISTRIBUTION_TABLE
        | PropertyIdentifier::BBMD_FOREIGN_DEVICE_TABLE
        | PropertyIdentifier::MANUAL_SLAVE_ADDRESS_BINDING
        | PropertyIdentifier::SLAVE_ADDRESS_BINDING
        | PropertyIdentifier::VIRTUAL_MAC_ADDRESS_TABLE
        | PropertyIdentifier::ROUTING_TABLE
        | PropertyIdentifier::LANDING_CALLS
        | PropertyIdentifier::FAULT_SIGNALS => true,
        PropertyIdentifier::ALARM_VALUES | PropertyIdentifier::FAULT_VALUES => !matches!(
            object_type,
            ObjectType::CHARACTERSTRING_VALUE | ObjectType::BITSTRING_VALUE
        ),
        PropertyIdentifier::LIST_OF_OBJECT_PROPERTY_REFERENCES => {
            object_type != ObjectType::CHANNEL
        }
        PropertyIdentifier::PRESENT_VALUE => object_type == ObjectType::GROUP,
        PropertyIdentifier::MEMBER_OF => matches!(
            object_type,
            ObjectType::LIFE_SAFETY_POINT | ObjectType::LIFE_SAFETY_ZONE | ObjectType::ACCESS_USER
        ),
        _ => false,
    }
}

/// The historical PICS writable-property heuristic, used by the default
/// [`super::BACnetObject::is_writable_property`] so unmigrated object types keep
/// their current PICS output.
///
/// This is a free function (not a per-object override) so the default trait
/// method can delegate to it without requiring `Self: Sized` (which would
/// break `dyn BACnetObject` dispatch). Object implementations should override
/// [`super::BACnetObject::is_writable_property`] to mirror their real
/// `write_property` arms exactly rather than calling this.
#[inline]
pub(super) fn historical_writable_default(
    object_type: ObjectType,
    property: PropertyIdentifier,
) -> bool {
    // Universal read-only properties.
    if property == PropertyIdentifier::OBJECT_IDENTIFIER
        || property == PropertyIdentifier::OBJECT_TYPE
        || property == PropertyIdentifier::PROPERTY_LIST
        || property == PropertyIdentifier::STATUS_FLAGS
    {
        return false;
    }

    if property == PropertyIdentifier::OBJECT_NAME {
        return true;
    }

    if property == PropertyIdentifier::PRESENT_VALUE {
        return object_type != ObjectType::ANALOG_INPUT
            && object_type != ObjectType::BINARY_INPUT
            && object_type != ObjectType::MULTI_STATE_INPUT;
    }

    property == PropertyIdentifier::DESCRIPTION
        || property == PropertyIdentifier::OUT_OF_SERVICE
        || property == PropertyIdentifier::COV_INCREMENT
        || property == PropertyIdentifier::HIGH_LIMIT
        || property == PropertyIdentifier::LOW_LIMIT
        || property == PropertyIdentifier::DEADBAND
        || property == PropertyIdentifier::NOTIFICATION_CLASS
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn list_classification_follows_the_datatype_and_never_overlaps_arrays() {
        for object_type in (0..=63).map(ObjectType::from_raw) {
            for property in (0..=1023).map(PropertyIdentifier::from_raw) {
                assert!(
                    !(array_property_default(object_type, property)
                        && list_property_default(object_type, property)),
                    "{object_type:?} {property:?} is both an array and a list"
                );
            }
        }
        let cases = [
            (ObjectType::CALENDAR, PropertyIdentifier::DATE_LIST, true),
            (
                ObjectType::NOTIFICATION_CLASS,
                PropertyIdentifier::RECIPIENT_LIST,
                true,
            ),
            (
                ObjectType::ELEVATOR_GROUP,
                PropertyIdentifier::LANDING_CALLS,
                true,
            ),
            (
                ObjectType::MULTI_STATE_INPUT,
                PropertyIdentifier::ALARM_VALUES,
                true,
            ),
            (
                ObjectType::CHARACTERSTRING_VALUE,
                PropertyIdentifier::ALARM_VALUES,
                false,
            ),
            (
                ObjectType::BITSTRING_VALUE,
                PropertyIdentifier::ALARM_VALUES,
                false,
            ),
            (
                ObjectType::SCHEDULE,
                PropertyIdentifier::LIST_OF_OBJECT_PROPERTY_REFERENCES,
                true,
            ),
            (
                ObjectType::CHANNEL,
                PropertyIdentifier::LIST_OF_OBJECT_PROPERTY_REFERENCES,
                false,
            ),
            (ObjectType::GROUP, PropertyIdentifier::PRESENT_VALUE, true),
            (
                ObjectType::GLOBAL_GROUP,
                PropertyIdentifier::PRESENT_VALUE,
                false,
            ),
            (
                ObjectType::DATETIME_VALUE,
                PropertyIdentifier::PRESENT_VALUE,
                false,
            ),
            (
                ObjectType::LIFE_SAFETY_ZONE,
                PropertyIdentifier::MEMBER_OF,
                true,
            ),
            (ObjectType::AUDIT_LOG, PropertyIdentifier::MEMBER_OF, false),
            (
                ObjectType::ELEVATOR_GROUP,
                PropertyIdentifier::LANDING_CALL_CONTROL,
                false,
            ),
            (
                ObjectType::MULTI_STATE_VALUE,
                PropertyIdentifier::STATE_TEXT,
                false,
            ),
            (ObjectType::DEVICE, PropertyIdentifier::OBJECT_LIST, false),
            (ObjectType::DEVICE, PropertyIdentifier::PROPERTY_LIST, false),
        ];
        for (object_type, property, list) in cases {
            assert_eq!(
                list_property_default(object_type, property),
                list,
                "{object_type:?} {property:?}"
            );
        }
    }
}
