use bacnet_types::enums::PropertyIdentifier as P;

use crate::property_metadata::{
    PropertyConformance::{Optional, RequiredRead, RequiredWrite},
    PropertyMetadata,
    PropertyWriteCapability::{Always, ReadOnly},
};

// Effective rows for Channel (type 53, ASHRAE 135-2020 Clause 12.53,
// Table 12-62), in table order with PROPERTY_LIST last. Only the rows the
// object serves are listed: Reliability, the intrinsic-reporting rows,
// Value_Source, the audit rows, Tags and the profile rows stay absent.
// Present_Value, List_Of_Object_Property_References, Channel_Number and
// Control_Groups carry the table's W code. Out_Of_Service carries R but takes
// writes, as Clause 12.53.10 has a client set it to decouple the value from
// the members. Execution_Delay is optional and always present here; Clause
// 12.53.12 makes a present one writable. Allow_Group_Delay_Inhibit is
// optional, always present and writable here, so a client can configure
// WriteGroup's delay inhibit. Object_Name and Description take
// CharacterString writes.
pub(super) const CHANNEL_PROPERTY_METADATA: &[PropertyMetadata] = &[
    PropertyMetadata::new(P::OBJECT_IDENTIFIER, RequiredRead, None, ReadOnly),
    PropertyMetadata::new(P::OBJECT_NAME, RequiredRead, None, Always),
    PropertyMetadata::new(P::OBJECT_TYPE, RequiredRead, None, ReadOnly),
    PropertyMetadata::new(P::DESCRIPTION, Optional, None, Always),
    PropertyMetadata::new(P::PRESENT_VALUE, RequiredWrite, None, Always),
    PropertyMetadata::new(P::LAST_PRIORITY, RequiredRead, None, ReadOnly),
    PropertyMetadata::new(P::WRITE_STATUS, RequiredRead, None, ReadOnly),
    PropertyMetadata::new(P::STATUS_FLAGS, RequiredRead, None, ReadOnly),
    PropertyMetadata::new(P::OUT_OF_SERVICE, RequiredRead, None, Always),
    PropertyMetadata::new(
        P::LIST_OF_OBJECT_PROPERTY_REFERENCES,
        RequiredWrite,
        None,
        Always,
    ),
    PropertyMetadata::new(P::EXECUTION_DELAY, Optional, None, Always),
    PropertyMetadata::new(P::ALLOW_GROUP_DELAY_INHIBIT, Optional, None, Always),
    PropertyMetadata::new(P::CHANNEL_NUMBER, RequiredWrite, None, Always),
    PropertyMetadata::new(P::CONTROL_GROUPS, RequiredWrite, None, Always),
    PropertyMetadata::new(P::PROPERTY_LIST, RequiredRead, None, ReadOnly),
];
