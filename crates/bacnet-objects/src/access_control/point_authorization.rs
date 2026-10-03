//! The authentication policy, authorization mode and door command priority
//! of an Access Point (Clauses 12.31.10, 12.31.11, 12.31.14 and 12.31.33;
//! #1307).
//!
//! The point doesn't serve Authentication_Policy_List or
//! Authentication_Policy_Names, so the content of each policy is left to the
//! application (12.31.12). What the point serves is how many policies there
//! are and which one is in effect:
//!
//! - Number_Of_Authentication_Policies is 1 until the application sets
//!   another count, which can't be zero. Over the network it is read-only.
//! - Active_Authentication_Policy is 1 until changed, and a client changes
//!   it with WriteProperty: an Unsigned from 1 to the count, else
//!   VALUE_OUT_OF_RANGE (12.31.10). Zero isn't one of the policies, so it is
//!   refused too.
//! - The application can't lower the count below the policy in effect. The
//!   active policy therefore stays at 1 or more, and the zero value, with
//!   the CONFIGURATION_ERROR Reliability that comes with it, never arises.
//!
//! Authorization_Mode is writable as well. Table K-10 names it, beside
//! Active_Authentication_Policy, among the Access Point properties an
//! access-control workstation (DS-ACM-A) changes in daily use. Clause
//! 12.31.14 lets a point carry out fewer than all the modes but never leave
//! out AUTHORIZE, so the point keeps the set of modes its application
//! supports: the six standard ones until the application gives another set,
//! which may add proprietary ones from 64. A written mode outside the set is
//! VALUE_OUT_OF_RANGE. AUTHORIZE is the mode a new point starts in.
//!
//! Priority_For_Writing is the priority the Access_Doors are commanded at
//! (12.31.32.1), 16 until the application sets another from 1 to 16. As on
//! the Loop it is read-only over the network.
//!
//! The point stores these values and checks them; carrying out a policy or a
//! mode, and commanding the doors, is the application's work.

use bacnet_types::enums::{AuthorizationMode, PropertyIdentifier as P};
use bacnet_types::error::Error;
use bacnet_types::primitives::PropertyValue;

use crate::common;

/// The standard BACnetAuthorizationMode values, the set a new point accepts.
const STANDARD_MODES: [AuthorizationMode; 6] = [
    AuthorizationMode::AUTHORIZE,
    AuthorizationMode::GRANT_ACTIVE,
    AuthorizationMode::DENY_ALL,
    AuthorizationMode::VERIFICATION_REQUIRED,
    AuthorizationMode::AUTHORIZATION_DELAYED,
    AuthorizationMode::NONE,
];

/// The first proprietary BACnetAuthorizationMode value; 6 to 63 are kept
/// for the standard (Clause 21).
const FIRST_PROPRIETARY_MODE: u32 = 64;

/// An Access Point's policy, mode and priority settings.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct Authorization {
    /// Number_Of_Authentication_Policies, at least 1.
    policies: u32,
    /// Active_Authentication_Policy, from 1 to `policies`.
    active_policy: u32,
    /// Authorization_Mode, always one of `supported_modes`.
    mode: AuthorizationMode,
    /// The modes Authorization_Mode can take, in numeric order, with
    /// AUTHORIZE always among them.
    supported_modes: Vec<AuthorizationMode>,
    /// Priority_For_Writing, from 1 to 16.
    priority_for_writing: u8,
}

impl Authorization {
    /// One policy, in effect; AUTHORIZE out of every standard mode; and the
    /// lowest command priority.
    pub(super) fn new() -> Self {
        Self {
            policies: 1,
            active_policy: 1,
            mode: AuthorizationMode::AUTHORIZE,
            supported_modes: STANDARD_MODES.to_vec(),
            priority_for_writing: 16,
        }
    }

    /// What one of the four rows reads, or `None` for another property.
    pub(super) fn read(&self, property: P) -> Option<PropertyValue> {
        Some(match property {
            P::ACTIVE_AUTHENTICATION_POLICY => PropertyValue::Unsigned(self.active_policy.into()),
            P::NUMBER_OF_AUTHENTICATION_POLICIES => PropertyValue::Unsigned(self.policies.into()),
            P::AUTHORIZATION_MODE => PropertyValue::Enumerated(self.mode.to_raw()),
            P::PRIORITY_FOR_WRITING => PropertyValue::Unsigned(self.priority_for_writing.into()),
            _ => return None,
        })
    }

    /// A client's write of Active_Authentication_Policy or
    /// Authorization_Mode, or `None` for another property. Neither is an
    /// array, so an index is PROPERTY_IS_NOT_AN_ARRAY; a refusal changes
    /// nothing.
    pub(super) fn write(
        &mut self,
        property: P,
        array_index: Option<u32>,
        value: &PropertyValue,
    ) -> Option<Result<(), Error>> {
        if property != P::ACTIVE_AUTHENTICATION_POLICY && property != P::AUTHORIZATION_MODE {
            return None;
        }
        if array_index.is_some() {
            return Some(Err(common::property_is_not_an_array_error()));
        }
        Some(if property == P::ACTIVE_AUTHENTICATION_POLICY {
            self.write_active_policy(value)
        } else {
            self.write_mode(value)
        })
    }

    /// An Unsigned naming one of the policies, else INVALID_DATA_TYPE or
    /// VALUE_OUT_OF_RANGE.
    fn write_active_policy(&mut self, value: &PropertyValue) -> Result<(), Error> {
        let PropertyValue::Unsigned(policy) = *value else {
            return Err(common::invalid_data_type_error());
        };
        self.active_policy = u32::try_from(policy)
            .ok()
            .filter(|policy| (1..=self.policies).contains(policy))
            .ok_or_else(common::value_out_of_range_error)?;
        Ok(())
    }

    /// An Enumerated in the supported set, else INVALID_DATA_TYPE or
    /// VALUE_OUT_OF_RANGE.
    fn write_mode(&mut self, value: &PropertyValue) -> Result<(), Error> {
        let PropertyValue::Enumerated(raw) = *value else {
            return Err(common::invalid_data_type_error());
        };
        let mode = AuthorizationMode::from_raw(raw);
        if !self.supported_modes.contains(&mode) {
            return Err(common::value_out_of_range_error());
        }
        self.mode = mode;
        Ok(())
    }

    /// Replace the policy count: VALUE_OUT_OF_RANGE for zero or for a count
    /// below the policy in effect.
    pub(super) fn set_policies(&mut self, count: u32) -> Result<(), Error> {
        if count == 0 || count < self.active_policy {
            return Err(common::value_out_of_range_error());
        }
        self.policies = count;
        Ok(())
    }

    /// Replace the supported modes: VALUE_OUT_OF_RANGE for a mode outside
    /// the production's standard and proprietary values, or a set that
    /// leaves out AUTHORIZE or the mode in effect. Repeats collapse.
    pub(super) fn set_supported_modes(
        &mut self,
        modes: impl IntoIterator<Item = AuthorizationMode>,
    ) -> Result<(), Error> {
        let mut modes: Vec<_> = modes.into_iter().collect();
        if !modes.iter().all(|&mode| in_production(mode))
            || !modes.contains(&AuthorizationMode::AUTHORIZE)
            || !modes.contains(&self.mode)
        {
            return Err(common::value_out_of_range_error());
        }
        modes.sort_unstable_by_key(|mode| mode.to_raw());
        modes.dedup();
        self.supported_modes = modes;
        Ok(())
    }

    /// Replace Priority_For_Writing: VALUE_OUT_OF_RANGE outside 1 to 16.
    pub(super) fn set_priority_for_writing(&mut self, priority: u8) -> Result<(), Error> {
        if !(1..=16).contains(&priority) {
            return Err(common::value_out_of_range_error());
        }
        self.priority_for_writing = priority;
        Ok(())
    }
}

/// Whether `mode` is a standard BACnetAuthorizationMode or a proprietary
/// one: 0 to 5, or 64 to 65535.
fn in_production(mode: AuthorizationMode) -> bool {
    let raw = mode.to_raw();
    raw <= AuthorizationMode::NONE.to_raw() || (FIRST_PROPRIETARY_MODE..=65_535).contains(&raw)
}
