//! The constructed values of the Color and Color Temperature objects
//! (Addendum 135-2020ca): a CIE 1931 xy colour and the Color_Command they
//! take.

use crate::enums::ColorOperation;

/// `BACnetxyColor` (Addendum 135-2020ca, Clause 21): a colour as its x and y
/// coordinates on the CIE 1931 chromaticity diagram.
///
/// It is a Color object's Present_Value, Tracking_Value and Default_Color,
/// and the target of a FADE_TO_COLOR command. On the wire it is the two
/// coordinates as application-tagged REALs, x first, with no tags of their
/// own around them; the `bacnet-encoding` crate owns the codec. The type
/// holds any two REALs: a Color object refuses a coordinate outside 0.0 to
/// 1.0 where it takes one.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct BACnetXyColor {
    /// The x coordinate.
    pub x: f32,
    /// The y coordinate.
    pub y: f32,
}

impl BACnetXyColor {
    /// The colour at `(x, y)`.
    pub const fn new(x: f32, y: f32) -> Self {
        Self { x, y }
    }
}

/// `BACnetColorCommand` (Addendum 135-2020ca, Clause 21): a colour operation
/// and the parameters it may carry.
///
/// A Color or Color Temperature object serves the last one written as
/// Color_Command. On the wire it is a SEQUENCE with no frame of its own: the
/// operation under primitive context tag `[0]`, then whichever optional
/// fields are present, in ascending tag order. The target colour `[1]` is a
/// [`BACnetXyColor`] between an opening and a closing tag `[1]`; the target
/// colour temperature `[2]`, fade time `[3]`, ramp rate `[4]` and step
/// increment `[5]` are primitive Unsigneds. The `bacnet-encoding` crate owns
/// the codec.
///
/// The type holds any values that fit its fields. Which operations an object
/// takes, which fields each uses and their ranges are for the object to
/// check; both colour objects do so on every write.
///
/// ```
/// use bacnet_types::constructed::{BACnetColorCommand, BACnetXyColor};
/// use bacnet_types::enums::ColorOperation;
///
/// // Fade to D65 white over two seconds.
/// let fade = BACnetColorCommand {
///     target_color: Some(BACnetXyColor::new(0.3127, 0.3290)),
///     fade_time: Some(2_000),
///     ..BACnetColorCommand::new(ColorOperation::FADE_TO_COLOR)
/// };
/// assert_eq!(fade.target_color_temperature, None);
/// ```
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct BACnetColorCommand {
    /// Context tag 0: the operation requested.
    pub operation: ColorOperation,
    /// Context tag 1: the colour a FADE_TO_COLOR ends at.
    pub target_color: Option<BACnetXyColor>,
    /// Context tag 2: the colour temperature, in kelvin, a FADE_TO_CCT or
    /// RAMP_TO_CCT ends at.
    pub target_color_temperature: Option<u32>,
    /// Context tag 3: how long a fade takes, in milliseconds.
    pub fade_time: Option<u32>,
    /// Context tag 4: how fast a RAMP_TO_CCT moves, in kelvin per second.
    pub ramp_rate: Option<u32>,
    /// Context tag 5: how far a STEP_UP_CCT or STEP_DOWN_CCT moves, in
    /// kelvin.
    pub step_increment: Option<u32>,
}

impl BACnetColorCommand {
    /// A command for `operation` that carries no other field.
    pub const fn new(operation: ColorOperation) -> Self {
        Self {
            operation,
            target_color: None,
            target_color_temperature: None,
            fade_time: None,
            ramp_rate: None,
            step_increment: None,
        }
    }
}
