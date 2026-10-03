//! Coercing a Channel's value to each member's datatype (Clause 12.53.5.1,
//! Table 12-63 and Coercion Rules 1 to 6 in Clauses 12.53.5.2 to 12.53.5.7).
//!
//! The table is keyed by the datatype written to Present_Value and the
//! datatype of the member property. A pair it marks as needing no coercion
//! passes the value on; a pair it marks as an invalid datatype, or a number
//! outside a rule's limits, is a coercion failure: the member isn't written
//! and the distribution ends FAILED (Clause 12.53.5.8).
//!
//! Choices this module makes where the clause leaves room:
//!
//! - A member's datatype is that of the value its property holds now (see
//!   [`MemberDatatype::of`]); a NULL or constructed value counts as unknown,
//!   which takes any value but a lighting command, as the table's first
//!   column does.
//! - Where the table passes a value on between two different datatypes
//!   (Unsigned and ENUMERATED, Unsigned and BACnetObjectIdentifier), the
//!   number is kept and only the datatype changes. A number the target can't
//!   hold is a failure.
//! - Rule 3 bounds an Unsigned or ENUMERATED value at 2147483647 when it goes
//!   to an INTEGER, the one target where that bound bites; REAL and Double
//!   targets take any Unsigned.
//! - A REAL or Double going to an integer type keeps its integer part
//!   (truncation toward zero) once the rule's range check passes. NaN is
//!   outside every range.
//! - The REAL precision limit in Rules 3 and 4 is the rounding a REAL does
//!   anyway, not a failure.

use bacnet_encoding::constructed::is_lighting_command_channel_value;
use bacnet_types::enums::PropertyIdentifier;
use bacnet_types::primitives::{ObjectIdentifier, PropertyValue};

/// The datatype of a Channel member's property, as Table 12-63's columns
/// name them.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MemberDatatype {
    /// Not known: any value but a lighting command passes on unchanged.
    Unknown,
    /// BOOLEAN.
    Boolean,
    /// Unsigned.
    Unsigned,
    /// INTEGER.
    Integer,
    /// REAL.
    Real,
    /// Double.
    Double,
    /// OCTET STRING.
    OctetString,
    /// CharacterString.
    CharacterString,
    /// BIT STRING.
    BitString,
    /// ENUMERATED.
    Enumerated,
    /// Date.
    Date,
    /// Time.
    Time,
    /// BACnetObjectIdentifier.
    ObjectIdentifier,
    /// BACnetLightingCommand.
    LightingCommand,
}

impl MemberDatatype {
    /// The datatype of member property `property`, whose value is `current`
    /// (`None` when it can't be read).
    ///
    /// Lighting_Command is a BACnetLightingCommand whatever form the object
    /// keeps it in. Any other property takes the datatype of the primitive
    /// it holds; NULL, constructed values and unreadable properties are
    /// [`MemberDatatype::Unknown`].
    pub fn of(property: PropertyIdentifier, current: Option<&PropertyValue>) -> Self {
        if property == PropertyIdentifier::LIGHTING_COMMAND {
            return Self::LightingCommand;
        }
        match current {
            Some(PropertyValue::Boolean(_)) => Self::Boolean,
            Some(PropertyValue::Unsigned(_)) => Self::Unsigned,
            Some(PropertyValue::Signed(_)) => Self::Integer,
            Some(PropertyValue::Real(_)) => Self::Real,
            Some(PropertyValue::Double(_)) => Self::Double,
            Some(PropertyValue::OctetString(_)) => Self::OctetString,
            Some(PropertyValue::CharacterString(_)) => Self::CharacterString,
            Some(PropertyValue::BitString { .. }) => Self::BitString,
            Some(PropertyValue::Enumerated(_)) => Self::Enumerated,
            Some(PropertyValue::Date(_)) => Self::Date,
            Some(PropertyValue::Time(_)) => Self::Time,
            Some(PropertyValue::ObjectIdentifier(_)) => Self::ObjectIdentifier,
            _ => Self::Unknown,
        }
    }
}

/// A channel value that can't go to a member: the table names an invalid
/// datatype, or a number is outside its rule's limits.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CoercionFailure;

/// A number a channel value carries, by the coercion rule its datatype
/// follows.
#[derive(Clone, Copy)]
enum Number {
    /// BOOLEAN, as 0 or 1 (Rule 2).
    Boolean(bool),
    /// Unsigned or ENUMERATED (Rule 3).
    Unsigned(u64),
    /// INTEGER (Rule 4).
    Integer(i64),
    /// REAL (Rule 5).
    Real(f32),
    /// Double (Rule 6).
    Double(f64),
}

/// Rules 5 and 6 bound a REAL or Double going to an Unsigned or ENUMERATED
/// at this value, and to an INTEGER at it either way.
const FLOAT_TO_INTEGER_LIMIT: f64 = 2_147_483_000.0;

impl Number {
    fn of(value: &PropertyValue) -> Option<Self> {
        Some(match *value {
            PropertyValue::Boolean(value) => Self::Boolean(value),
            PropertyValue::Unsigned(value) => Self::Unsigned(value),
            PropertyValue::Enumerated(value) => Self::Unsigned(value.into()),
            PropertyValue::Signed(value) => Self::Integer(value.into()),
            PropertyValue::Real(value) => Self::Real(value),
            PropertyValue::Double(value) => Self::Double(value),
            _ => return None,
        })
    }

    /// Rule 1: zero is FALSE and anything else TRUE.
    fn to_boolean(self) -> bool {
        match self {
            Self::Boolean(value) => value,
            Self::Unsigned(value) => value != 0,
            Self::Integer(value) => value != 0,
            Self::Real(value) => value != 0.0,
            Self::Double(value) => value != 0.0,
        }
    }

    /// The value as an Unsigned or ENUMERATED, if the rule allows it.
    fn to_unsigned(self) -> Option<u64> {
        match self {
            Self::Boolean(value) => Some(value.into()),
            Self::Unsigned(value) => Some(value),
            // Rule 4's upper bound, 2147483647, is the top of the INTEGER
            // range, so only the sign can fail.
            Self::Integer(value) => u64::try_from(value).ok(),
            Self::Real(value) => float_to_unsigned(value.into()),
            Self::Double(value) => float_to_unsigned(value),
        }
    }

    /// The value as an INTEGER, if the rule allows it.
    fn to_integer(self) -> Option<i32> {
        match self {
            Self::Boolean(value) => Some(value.into()),
            // Rule 3's bound, 2147483647, is the top of the INTEGER range.
            Self::Unsigned(value) => i32::try_from(value).ok(),
            Self::Integer(value) => i32::try_from(value).ok(),
            Self::Real(value) => float_to_integer(value.into()),
            Self::Double(value) => float_to_integer(value),
        }
    }

    /// The value as a REAL, if the rule allows it.
    fn to_real(self) -> Option<f32> {
        match self {
            Self::Boolean(value) => Some(u8::from(value).into()),
            Self::Unsigned(value) => Some(value as f32),
            Self::Integer(value) => Some(value as f32),
            Self::Real(value) => Some(value),
            // Rule 6: a magnitude past the REAL range fails.
            Self::Double(value) => {
                (value.abs() <= f64::from(f32::MAX) || value.is_nan()).then_some(value as f32)
            }
        }
    }

    /// The value as a Double.
    fn to_double(self) -> f64 {
        match self {
            Self::Boolean(value) => u8::from(value).into(),
            Self::Unsigned(value) => value as f64,
            Self::Integer(value) => value as f64,
            Self::Real(value) => value.into(),
            Self::Double(value) => value,
        }
    }
}

fn float_to_unsigned(value: f64) -> Option<u64> {
    (0.0..=FLOAT_TO_INTEGER_LIMIT)
        .contains(&value)
        .then(|| value.trunc() as u64)
}

fn float_to_integer(value: f64) -> Option<i32> {
    (-FLOAT_TO_INTEGER_LIMIT..=FLOAT_TO_INTEGER_LIMIT)
        .contains(&value)
        .then(|| value.trunc() as i32)
}

/// The value a member of datatype `target` gets when a Channel holding
/// `value` distributes it (Table 12-63).
///
/// A lighting command, held as its context-\[0\] octets, reaches a
/// BACnetLightingCommand member as the SEQUENCE inside that tag, the way a
/// WriteProperty to Lighting_Command carries it.
pub fn coerce_channel_value(
    value: &PropertyValue,
    target: MemberDatatype,
) -> Result<PropertyValue, CoercionFailure> {
    use MemberDatatype as D;

    if let PropertyValue::ApplicationData(octets) = value {
        // The only constructed channel value: it goes to a lighting command
        // member and nowhere else, not even an unknown one.
        if target == D::LightingCommand && is_lighting_command_channel_value(octets) {
            return Ok(PropertyValue::ApplicationData(
                octets[1..octets.len() - 1].to_vec(),
            ));
        }
        return Err(CoercionFailure);
    }
    match target {
        D::LightingCommand => return Err(CoercionFailure),
        D::Unknown => return Ok(value.clone()),
        _ => {}
    }
    if *value == PropertyValue::Null {
        return Ok(PropertyValue::Null);
    }
    if let Some(number) = Number::of(value) {
        let coerced = match target {
            D::Boolean => Some(PropertyValue::Boolean(number.to_boolean())),
            D::Unsigned => number.to_unsigned().map(PropertyValue::Unsigned),
            D::Integer => number.to_integer().map(PropertyValue::Signed),
            D::Real => number.to_real().map(PropertyValue::Real),
            D::Double => Some(PropertyValue::Double(number.to_double())),
            D::Enumerated => number
                .to_unsigned()
                .and_then(|raw| u32::try_from(raw).ok())
                .map(PropertyValue::Enumerated),
            // The table passes an Unsigned to an object identifier as the
            // same 32-bit number.
            D::ObjectIdentifier => match *value {
                PropertyValue::Unsigned(raw) => u32::try_from(raw)
                    .ok()
                    .and_then(|raw| ObjectIdentifier::decode(&raw.to_be_bytes()).ok())
                    .map(PropertyValue::ObjectIdentifier),
                _ => None,
            },
            _ => None,
        };
        return coerced.ok_or(CoercionFailure);
    }
    let passes = match (value, target) {
        (PropertyValue::OctetString(_), D::OctetString)
        | (PropertyValue::CharacterString(_), D::CharacterString)
        | (PropertyValue::BitString { .. }, D::BitString)
        | (PropertyValue::Date(_), D::Date)
        | (PropertyValue::Time(_), D::Time)
        | (PropertyValue::ObjectIdentifier(_), D::ObjectIdentifier) => true,
        (PropertyValue::ObjectIdentifier(oid), D::Unsigned) => {
            return Ok(PropertyValue::Unsigned(
                u32::from_be_bytes(oid.encode()).into(),
            ));
        }
        _ => false,
    };
    if passes {
        Ok(value.clone())
    } else {
        Err(CoercionFailure)
    }
}
