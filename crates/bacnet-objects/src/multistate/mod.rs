//! Multi-State Input (type 13), Multi-State Output (type 14), and
//! Multi-State Value (type 19) objects per ASHRAE 135-2020 Clauses 12.18,
//! 12.19, and 12.20.

use bacnet_types::enums::{
    ErrorClass, ErrorCode, EventState, ObjectType, PropertyIdentifier, Reliability,
};
use bacnet_types::error::Error;
use bacnet_types::primitives::{BACnetTimeStamp, ObjectIdentifier, PropertyValue, StatusFlags};
use std::borrow::Cow;

use crate::common::{
    self, read_common_properties, read_generic_event_properties, write_generic_event_properties,
};
use crate::event::{history::EventHistory, ChangeOfStateDetector};
use crate::traits::{BACnetObject, ReliabilityEvaluation};

/// Resource cap consistent with bounded server tables such as
/// `MAX_COV_SUBSCRIPTIONS`.
pub(crate) const MAX_ALARM_VALUES: usize = 1024;

fn decode_alarm_values_write(
    array_index: Option<u32>,
    value: PropertyValue,
) -> Result<Vec<u32>, Error> {
    if array_index.is_some() {
        return Err(Error::Protocol {
            class: ErrorClass::PROPERTY.to_raw() as u32,
            code: ErrorCode::PROPERTY_IS_NOT_AN_ARRAY.to_raw() as u32,
        });
    }
    let PropertyValue::List(values) = value else {
        return Err(common::invalid_data_type_error());
    };
    // A refusal names its element (#1048); the first one past the cap is the
    // element that does not fit.
    if values.len() > MAX_ALARM_VALUES {
        return Err(common::at_list_element(
            Error::Protocol {
                class: ErrorClass::RESOURCES.to_raw() as u32,
                code: ErrorCode::NO_SPACE_TO_WRITE_PROPERTY.to_raw() as u32,
            },
            MAX_ALARM_VALUES,
        ));
    }
    values
        .into_iter()
        .enumerate()
        .map(|(index, value)| {
            match value {
                PropertyValue::Unsigned(value) => common::u64_to_u32(value),
                _ => Err(common::invalid_data_type_error()),
            }
            .map_err(|error| common::at_list_element(error, index))
        })
        .collect()
}

/// Reject a `number_of_states` of zero.
///
/// Every multi-state object starts `PRESENT_VALUE` (and, for Output/Value, the
/// relinquish default) at 1, and accepts writes only in `1..=number_of_states`.
/// With zero states that initial value is out of range with no attainable value,
/// so the constructors centralize this guard here.
fn require_nonzero_states(number_of_states: u32) -> Result<(), Error> {
    if number_of_states == 0 {
        return Err(Error::OutOfRange(
            "number_of_states must be at least 1".into(),
        ));
    }
    Ok(())
}

/// Resize an object's State_Text with the repository's local count-change policy.
///
/// Validation precedes mutation. Shrink truncates the tail, while growth keeps
/// the retained prefix and appends the same `State {n}` labels as construction.
fn resize_state_text(
    current_number_of_states: &mut u32,
    state_text: &mut Vec<String>,
    number_of_states: u32,
) -> Result<(), Error> {
    require_nonzero_states(number_of_states)?;
    let new_len = number_of_states as usize;
    if new_len < state_text.len() {
        state_text.truncate(new_len);
    } else {
        state_text.extend((state_text.len() + 1..=new_len).map(|state| format!("State {state}")));
    }
    *current_number_of_states = number_of_states;
    Ok(())
}

/// What a multi-state object takes only from a CreateObject initial value
/// (#1429): Number_Of_States, and State_Text written whole. WriteProperty
/// refuses both; a State_Text element stays writable.
const CREATION_ONLY: &[PropertyIdentifier] = &[
    PropertyIdentifier::NUMBER_OF_STATES,
    PropertyIdentifier::STATE_TEXT,
];

/// The most states a CreateObject initial value may give a multi-state
/// object. State_Text keeps a label for every state, so the count a client
/// picks is bounded like the other tables a client sizes.
pub const MAX_CREATED_NUMBER_OF_STATES: u32 = 1024;

/// Apply a CreateObject initial value to Number_Of_States or to the whole of
/// State_Text (#1429), checked before anything changes.
///
/// A state count runs from 1 to [`MAX_CREATED_NUMBER_OF_STATES`]. It is also
/// VALUE_OUT_OF_RANGE when one of `held`, the values the object keeps that
/// name a state (Present_Value, Relinquish_Default, the commands in
/// Priority_Array, Alarm_Values), would fall outside it. A new count resizes
/// State_Text as [`resize_state_text`] does (Clause 12.20.10 ties the two
/// sizes together). State_Text needs exactly one CharacterString per state,
/// VALUE_OUT_OF_RANGE for any other count; a single label arrives as that
/// CharacterString, the way a one-element array value decodes. Any other
/// property is WRITE_ACCESS_DENIED, as the trait default answers.
fn initialize_states(
    number_of_states: &mut u32,
    state_text: &mut Vec<String>,
    held: impl IntoIterator<Item = u32>,
    property: PropertyIdentifier,
    value: PropertyValue,
) -> Result<(), Error> {
    match property {
        PropertyIdentifier::NUMBER_OF_STATES => {
            let PropertyValue::Unsigned(count) = value else {
                return Err(common::invalid_data_type_error());
            };
            let count = u32::try_from(count)
                .ok()
                .filter(|count| (1..=MAX_CREATED_NUMBER_OF_STATES).contains(count))
                .ok_or_else(common::value_out_of_range_error)?;
            if held.into_iter().any(|state| !(1..=count).contains(&state)) {
                return Err(common::value_out_of_range_error());
            }
            resize_state_text(number_of_states, state_text, count)
        }
        PropertyIdentifier::STATE_TEXT => {
            let labels = match value {
                PropertyValue::CharacterString(label) => vec![label],
                PropertyValue::List(values) => values
                    .into_iter()
                    .map(|value| match value {
                        PropertyValue::CharacterString(label) => Ok(label),
                        _ => Err(common::invalid_data_type_error()),
                    })
                    .collect::<Result<Vec<_>, _>>()?,
                _ => return Err(common::invalid_data_type_error()),
            };
            if labels.len() != *number_of_states as usize {
                return Err(common::value_out_of_range_error());
            }
            *state_text = labels;
            Ok(())
        }
        _ => Err(common::write_access_denied_error()),
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum OwnedMultiStateFault {
    ConfigurationError,
    MultiStateOutOfRange,
}

impl OwnedMultiStateFault {
    fn reliability(self) -> Reliability {
        match self {
            Self::ConfigurationError => Reliability::CONFIGURATION_ERROR,
            Self::MultiStateOutOfRange => Reliability::MULTI_STATE_OUT_OF_RANGE,
        }
    }
}

/// Private first-stage Reliability ownership shared by MSI, MSO, and MSV.
#[derive(Debug, Default)]
struct MultiStateReliabilityState {
    pub(crate) owned_fault: Option<OwnedMultiStateFault>,
}

impl MultiStateReliabilityState {
    fn clear_ownership(&mut self) {
        self.owned_fault = None;
    }

    fn evaluate(
        &mut self,
        configuration_invalid: bool,
        present_value: u32,
        number_of_states: u32,
        reliability: &mut Reliability,
    ) -> ReliabilityEvaluation {
        let observed_fault = if configuration_invalid {
            Some(OwnedMultiStateFault::ConfigurationError)
        } else if !(1..=number_of_states).contains(&present_value) {
            Some(OwnedMultiStateFault::MultiStateOutOfRange)
        } else {
            None
        };

        let (new_reliability, new_owner) = if self.owned_fault.is_some() {
            (
                observed_fault
                    .map(OwnedMultiStateFault::reliability)
                    .unwrap_or(Reliability::NO_FAULT_DETECTED),
                observed_fault,
            )
        } else if *reliability == Reliability::NO_FAULT_DETECTED {
            let Some(fault) = observed_fault else {
                return ReliabilityEvaluation::Unchanged;
            };
            (fault.reliability(), Some(fault))
        } else {
            return ReliabilityEvaluation::Unchanged;
        };

        // Ownership can change while Reliability is already zero, notably when
        // inhibit normalized an owned fault and its source recovered before the
        // gate reopened. Keep the private state current even without a public
        // Reliability transition.
        self.owned_fault = new_owner;
        if new_reliability == *reliability {
            return ReliabilityEvaluation::Unchanged;
        }
        let old_reliability = *reliability;
        *reliability = new_reliability;
        ReliabilityEvaluation::Changed {
            old_reliability,
            new_reliability,
        }
    }
}

mod input;
mod output;
mod value;
pub use input::*;
pub use output::*;
pub use value::*;
#[cfg(test)]
mod tests;
