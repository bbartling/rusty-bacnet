//! The constructed value of a Lighting Output's Lighting_Command (Clause
//! 12.54).

use crate::enums::LightingOperation;

/// `BACnetLightingCommand` (Clause 21): a lighting operation and the
/// parameters it may carry.
///
/// A Lighting Output serves the last one written as Lighting_Command, and a
/// Channel can pass one to its members (Clause 12.53). On the wire it is a
/// SEQUENCE of primitive context tags in ascending order: the operation `[0]`,
/// then whichever of the target level `[1]`, ramp rate `[2]`, step increment
/// `[3]` (each a REAL), fade time `[4]` and priority `[5]` (each an Unsigned)
/// are present. The `bacnet-encoding` crate owns the codec.
///
/// The type holds any values that fit its fields. Which fields an operation
/// uses, and their ranges, are for the object that takes the command to
/// check; a Lighting Output does so on every write (Table 12-67).
///
/// ```
/// use bacnet_types::constructed::BACnetLightingCommand;
/// use bacnet_types::enums::LightingOperation;
///
/// // Fade to 40 % over two seconds at priority 8.
/// let fade = BACnetLightingCommand {
///     target_level: Some(40.0),
///     fade_time: Some(2_000),
///     priority: Some(8),
///     ..BACnetLightingCommand::new(LightingOperation::FADE_TO)
/// };
/// assert_eq!(fade.ramp_rate, None);
/// ```
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct BACnetLightingCommand {
    /// Context tag 0: the operation requested.
    pub operation: LightingOperation,
    /// Context tag 1: the level to fade or ramp to, in percent.
    pub target_level: Option<f32>,
    /// Context tag 2: the ramp rate, in percent per second.
    pub ramp_rate: Option<f32>,
    /// Context tag 3: the amount a step changes the level by, in percent.
    pub step_increment: Option<f32>,
    /// Context tag 4: how long a fade takes, in milliseconds.
    pub fade_time: Option<u32>,
    /// Context tag 5: the priority the command acts at, 1 (highest) to 16.
    pub priority: Option<u8>,
}

impl BACnetLightingCommand {
    /// A command for `operation` that carries no other field.
    pub const fn new(operation: LightingOperation) -> Self {
        Self {
            operation,
            target_level: None,
            ramp_rate: None,
            step_increment: None,
            fade_time: None,
            priority: None,
        }
    }
}
