use super::{ColorObject, ColorTemperatureObject};
use std::borrow::Cow;

use bacnet_types::enums::PropertyIdentifier as P;

use crate::audit::ObjectAuditPolicy;
use crate::property_metadata::{
    PropertyConformance::{Optional, RequiredRead, RequiredWrite},
    PropertyMetadata,
    PropertyWriteCapability::{Always, ReadOnly},
};

// The rows follow the addendum's property tables (Table 12-X for Color,
// Table 12-Y for Color Temperature), in their order, with Property_List
// last so the projection helper leaves it out (#1474).
//
// - Conformance is the table's code: W for Present_Value and Color_Command,
//   R or O for the rest.
// - Writability mirrors the write arms. Besides the two W rows, the defaults
//   and Transition take writes, each checked against the range its subclause
//   gives. Min_Pres_Value and Max_Pres_Value are set only through
//   `set_min_max`.
// - Neither table has Status_Flags, Event_State, Reliability or
//   Out_Of_Service, so neither object serves them.
// - Audit_Level and Auditable_Operations are present only once
//   `set_audit_policy` provisions them, as on an Analog or Binary Value
//   (#1525): the tables put them in only where the device does audit
//   reporting. They go in table order, after Transition.
// - Optional rows the objects don't implement are absent: Value_Source
//   (no noncommandable object tracks a value source), Tags, Profile_Location
//   and Profile_Name (no object serves them). Color Temperature's
//   Min_Pres_Value and Max_Pres_Value are implemented as a pair, as the
//   table's footnote asks.
// - Presence is None on every base row, and neither object is createable at
//   runtime (the network factory doesn't build them). Property_List is the
//   only array; COV support is the objects' own `supports_cov`.
const COLOR_BASE: &[PropertyMetadata] = &[
    PropertyMetadata::new(P::OBJECT_IDENTIFIER, RequiredRead, None, ReadOnly),
    PropertyMetadata::new(P::OBJECT_NAME, RequiredRead, None, ReadOnly),
    PropertyMetadata::new(P::OBJECT_TYPE, RequiredRead, None, ReadOnly),
    PropertyMetadata::new(P::PRESENT_VALUE, RequiredWrite, None, Always),
    PropertyMetadata::new(P::TRACKING_VALUE, RequiredRead, None, ReadOnly),
    PropertyMetadata::new(P::COLOR_COMMAND, RequiredWrite, None, Always),
    PropertyMetadata::new(P::IN_PROGRESS, RequiredRead, None, ReadOnly),
    PropertyMetadata::new(P::DEFAULT_COLOR, RequiredRead, None, Always),
    PropertyMetadata::new(P::DESCRIPTION, Optional, None, Always),
    PropertyMetadata::new(P::DEFAULT_FADE_TIME, RequiredRead, None, Always),
    PropertyMetadata::new(P::TRANSITION, Optional, None, Always),
    PropertyMetadata::new(P::PROPERTY_LIST, RequiredRead, None, ReadOnly),
];

const COLOR_TEMPERATURE_BASE: &[PropertyMetadata] = &[
    PropertyMetadata::new(P::OBJECT_IDENTIFIER, RequiredRead, None, ReadOnly),
    PropertyMetadata::new(P::OBJECT_NAME, RequiredRead, None, ReadOnly),
    PropertyMetadata::new(P::OBJECT_TYPE, RequiredRead, None, ReadOnly),
    PropertyMetadata::new(P::PRESENT_VALUE, RequiredWrite, None, Always),
    PropertyMetadata::new(P::TRACKING_VALUE, RequiredRead, None, ReadOnly),
    PropertyMetadata::new(P::COLOR_COMMAND, RequiredWrite, None, Always),
    PropertyMetadata::new(P::IN_PROGRESS, RequiredRead, None, ReadOnly),
    PropertyMetadata::new(P::DEFAULT_COLOR_TEMPERATURE, RequiredRead, None, Always),
    PropertyMetadata::new(P::DESCRIPTION, Optional, None, Always),
    PropertyMetadata::new(P::DEFAULT_FADE_TIME, RequiredRead, None, Always),
    PropertyMetadata::new(P::DEFAULT_RAMP_RATE, RequiredRead, None, Always),
    PropertyMetadata::new(P::DEFAULT_STEP_INCREMENT, RequiredRead, None, Always),
    PropertyMetadata::new(P::MIN_PRES_VALUE, Optional, None, ReadOnly),
    PropertyMetadata::new(P::MAX_PRES_VALUE, Optional, None, ReadOnly),
    PropertyMetadata::new(P::TRANSITION, Optional, None, Always),
    PropertyMetadata::new(P::PROPERTY_LIST, RequiredRead, None, ReadOnly),
];

pub(super) fn for_color_object(object: &ColorObject) -> Cow<'_, [PropertyMetadata]> {
    with_audit(COLOR_BASE, object.audit_policy())
}

pub(super) fn for_color_temperature_object(
    object: &ColorTemperatureObject,
) -> Cow<'_, [PropertyMetadata]> {
    with_audit(COLOR_TEMPERATURE_BASE, object.audit_policy())
}

/// `base` with the provisioned audit rows put in before Property_List.
fn with_audit(
    base: &'static [PropertyMetadata],
    policy: &ObjectAuditPolicy,
) -> Cow<'static, [PropertyMetadata]> {
    if *policy == ObjectAuditPolicy::default() {
        return Cow::Borrowed(base);
    }
    let (property_list, rows) = base.split_last().expect("a Property_List row");
    let mut rows = rows.to_vec();
    rows.extend(policy.metadata());
    rows.push(*property_list);
    Cow::Owned(rows)
}
