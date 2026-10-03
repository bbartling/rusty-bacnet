//! Lighting_Command of the Lighting Output object (Clause 12.54): taking a
//! written `BACnetLightingCommand` and checking it against its operation.
//!
//! A write reaches the object as the SEQUENCE's octets in one
//! `ApplicationData`. Error pairings follow Clause 15.9.1.3 and the Loop
//! references (#1312): a value that doesn't open with the operation field,
//! such as any application-tagged value, is INVALID_DATA_TYPE; octets that then
//! fail to decode as exactly one command are INVALID_DATA_ENCODING; and a
//! command its operation can't take is VALUE_OUT_OF_RANGE.
//!
//! What an operation takes comes from Table 12-67 and the Lighting_Command
//! text of Clause 12.54:
//!
//! - NONE only reports that nothing was written, so a write of it is refused,
//!   as are the operations ASHRAE reserves (11 to 255) and anything past the
//!   enumeration's range (65,535).
//! - FADE_TO and RAMP_TO need a target level, 0.0 to 100.0.
//! - A fade time must be 100 to 86,400,000 ms where FADE_TO carries one; a
//!   ramp rate 0.1 to 100.0 where RAMP_TO does; a step increment 0.1 to 100.0
//!   where a step operation does; and a priority 1 to 16 on every standard
//!   operation.
//! - A field the operation has no use for is kept as written but not
//!   checked, since the clause has the object ignore it.
//! - A proprietary operation (256 to 65,535) is taken as it comes. The table
//!   gives it no fields, so none is checked.

use std::ops::RangeInclusive;

use bacnet_encoding::constructed::{decode_lighting_command, encode_lighting_command};
use bacnet_encoding::tags;
use bacnet_types::constructed::BACnetLightingCommand;
use bacnet_types::enums::LightingOperation;
use bacnet_types::error::Error;
use bacnet_types::primitives::PropertyValue;
use bytes::BytesMut;

use super::{lighting_percent, DEFAULT_FADE_TIME_MS};
use crate::common;

/// The BACnetLightingOperation values open to vendors (Clause 23).
const PROPRIETARY_OPERATIONS: RangeInclusive<u32> = 256..=65_535;

/// The fields beyond priority that an operation uses.
enum Uses {
    /// A target level, which must be present, and a fade time.
    Fade,
    /// A target level, which must be present, and a ramp rate.
    Ramp,
    /// A step increment.
    Step,
    /// Priority alone.
    Priority,
}

/// The fields `operation` uses: `None` for a proprietary operation, whose
/// fields go unchecked, and an error for one that can't be written.
fn uses(operation: LightingOperation) -> Result<Option<Uses>, Error> {
    Ok(Some(match operation {
        LightingOperation::FADE_TO => Uses::Fade,
        LightingOperation::RAMP_TO => Uses::Ramp,
        LightingOperation::STEP_UP
        | LightingOperation::STEP_DOWN
        | LightingOperation::STEP_ON
        | LightingOperation::STEP_OFF => Uses::Step,
        LightingOperation::WARN
        | LightingOperation::WARN_OFF
        | LightingOperation::WARN_RELINQUISH
        | LightingOperation::STOP => Uses::Priority,
        other if PROPRIETARY_OPERATIONS.contains(&other.to_raw()) => return Ok(None),
        _ => return Err(common::value_out_of_range_error()),
    }))
}

/// Refuse a present `value` outside `range`.
fn within<T: PartialOrd>(value: Option<T>, range: RangeInclusive<T>) -> Result<(), Error> {
    match value {
        Some(value) if !range.contains(&value) => Err(common::value_out_of_range_error()),
        _ => Ok(()),
    }
}

/// A target level that must be present and within 0.0 to 100.0.
fn target_level(command: &BACnetLightingCommand) -> Result<(), Error> {
    let level = command
        .target_level
        .ok_or_else(common::value_out_of_range_error)?;
    within(Some(level), 0.0..=100.0)
}

/// Check `command` against what its operation takes; see the module
/// documentation for the rules.
pub(super) fn check(command: &BACnetLightingCommand) -> Result<(), Error> {
    let Some(uses) = uses(command.operation)? else {
        return Ok(());
    };
    match uses {
        Uses::Fade => {
            target_level(command)?;
            within(command.fade_time, DEFAULT_FADE_TIME_MS)?;
        }
        Uses::Ramp => {
            target_level(command)?;
            if let Some(rate) = command.ramp_rate {
                lighting_percent(rate)?;
            }
        }
        Uses::Step => {
            if let Some(increment) = command.step_increment {
                lighting_percent(increment)?;
            }
        }
        Uses::Priority => {}
    }
    within(command.priority, 1..=16)
}

/// Decode and check a Lighting_Command write.
pub(super) fn decode_write(value: PropertyValue) -> Result<BACnetLightingCommand, Error> {
    let PropertyValue::ApplicationData(bytes) = value else {
        return Err(common::invalid_data_type_error());
    };
    match tags::decode_tag(&bytes, 0) {
        Ok((tag, _)) if tag.is_context(0) => {}
        Ok(_) => return Err(common::invalid_data_type_error()),
        Err(_) => return Err(common::invalid_data_encoding_error()),
    }
    // The codec reports a field too wide for its type as a local OutOfRange
    // error; any other failure is a broken encoding.
    let (command, end) = decode_lighting_command(&bytes, 0).map_err(|error| match error {
        Error::OutOfRange(_) => common::value_out_of_range_error(),
        _ => common::invalid_data_encoding_error(),
    })?;
    if end != bytes.len() {
        return Err(common::invalid_data_encoding_error());
    }
    check(&command)?;
    Ok(command)
}

/// The value Lighting_Command reads as.
pub(super) fn encode(command: &BACnetLightingCommand) -> PropertyValue {
    let mut encoded = BytesMut::new();
    encode_lighting_command(&mut encoded, command);
    PropertyValue::ApplicationData(encoded.to_vec())
}
