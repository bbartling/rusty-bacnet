//! How a Value object's Present_Value is written.

use std::borrow::Cow;

use bacnet_types::enums::PropertyIdentifier;

use crate::property_metadata::{
    PropertyMetadata, PropertyPresenceCondition, PropertyWriteCapability,
};

/// How peers and the local application write a Value object's Present_Value.
///
/// Priority_Array, Relinquish_Default, Current_Command_Priority and the
/// command-source properties are present only under [`Commandable`](Self::Commandable).
/// Under every access, Out_Of_Service TRUE keeps the local application from
/// changing Present_Value and lets peers write it for testing (Clause 12,
/// Out_Of_Service of each Value object).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum PresentValueAccess {
    /// The application sets Present_Value. Peers write it only while
    /// Out_Of_Service is TRUE.
    ReadOnly,
    /// A peer write replaces Present_Value, and so does the application.
    Writable,
    /// Peer writes go through Priority_Array, and the highest occupied
    /// priority is Present_Value (Clause 19.2).
    #[default]
    Commandable,
}

impl PresentValueAccess {
    /// Whether a row with this presence condition exists under this access.
    pub(crate) fn includes(self, condition: Option<PropertyPresenceCondition>) -> bool {
        self == Self::Commandable
            || !matches!(
                condition,
                Some(
                    PropertyPresenceCondition::Commandable
                        | PropertyPresenceCondition::CommandableAuditReporting
                        | PropertyPresenceCondition::ValueSourceTracking
                        | PropertyPresenceCondition::CommandableValueSourceTracking
                )
            )
    }

    /// `rows` as this access presents them: the rows it excludes removed, and
    /// Present_Value's write capability set to match.
    pub(crate) fn project(self, rows: Cow<'_, [PropertyMetadata]>) -> Cow<'_, [PropertyMetadata]> {
        let present_value = match self {
            Self::Commandable => return rows,
            Self::Writable => PropertyWriteCapability::Always,
            Self::ReadOnly => PropertyWriteCapability::WhenOutOfService,
        };

        Cow::Owned(
            rows.iter()
                .filter(|row| self.includes(row.presence_condition))
                .map(|row| {
                    if row.property_identifier == PropertyIdentifier::PRESENT_VALUE {
                        PropertyMetadata::new(
                            row.property_identifier,
                            row.conformance,
                            row.presence_condition,
                            present_value,
                        )
                    } else {
                        *row
                    }
                })
                .collect(),
        )
    }

    /// Whether `rows` hold `property` under a condition this access excludes.
    pub(crate) fn excludes(self, rows: &[PropertyMetadata], property: PropertyIdentifier) -> bool {
        self != Self::Commandable
            && rows.iter().any(|row| {
                row.property_identifier == property && !self.includes(row.presence_condition)
            })
    }
}
