//! Constructed values served by the Access Rights object (Clause 12.34), the
//! Access Credential object (Clause 12.35) and the Credential Data Input
//! object (Clause 12.36).

#[cfg(not(feature = "std"))]
use alloc::vec::Vec;

use super::{BACnetDeviceObjectPropertyReference, BACnetDeviceObjectReference};
use crate::enums::{
    AccessAuthenticationFactorDisable, AccessRuleLocationSpecifier, AccessRuleTimeRangeSpecifier,
    AuthenticationFactorType,
};

/// One element of an Access Rights object's Positive_Access_Rules or
/// Negative_Access_Rules array (`BACnetAccessRule`, Clause 21; Clause
/// 12.34.9.1).
///
/// The fields mirror the five wire members in order: the time-range
/// specifier as a context `[0]` ENUMERATED, the time-range reference framed
/// in context tag `[1]`, the location specifier as a context `[2]`
/// ENUMERATED, the location reference framed in context tag `[3]` and the
/// enable flag as a context `[4]` BOOLEAN. Both references are optional on
/// the wire. The codec is `bacnet_encoding::constructed::{encode_access_rule,
/// decode_access_rule}`; it keeps whatever specifier values it reads, and the
/// Access Rights setters refuse the combinations Clause 12.34.9.1 rules out.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BACnetAccessRule {
    /// SPECIFIED when `time_range` decides when the rule applies, ALWAYS
    /// when it applies at any time.
    pub time_range_specifier: AccessRuleTimeRangeSpecifier,
    /// The property, typically a Schedule's Present_Value, whose value says
    /// whether the rule applies now. Needed with SPECIFIED; with ALWAYS it is
    /// left out or unspecified (instance 4194303).
    pub time_range: Option<BACnetDeviceObjectPropertyReference>,
    /// SPECIFIED when `location` names the place the rule covers, ALL when
    /// it covers every access point.
    pub location_specifier: AccessRuleLocationSpecifier,
    /// Where the rule holds: an Access Point or an Access Zone. Needed with
    /// SPECIFIED; with ALL it is left out or unspecified.
    pub location: Option<BACnetDeviceObjectReference>,
    /// Whether the rule is in force.
    pub enable: bool,
}

impl BACnetAccessRule {
    /// A rule whose specifiers follow the references: SPECIFIED for each
    /// one given, ALWAYS for a missing time range and ALL for a missing
    /// location.
    pub fn new(
        time_range: Option<BACnetDeviceObjectPropertyReference>,
        location: Option<BACnetDeviceObjectReference>,
        enable: bool,
    ) -> Self {
        Self {
            time_range_specifier: if time_range.is_some() {
                AccessRuleTimeRangeSpecifier::SPECIFIED
            } else {
                AccessRuleTimeRangeSpecifier::ALWAYS
            },
            time_range,
            location_specifier: if location.is_some() {
                AccessRuleLocationSpecifier::SPECIFIED
            } else {
                AccessRuleLocationSpecifier::ALL
            },
            location,
            enable,
        }
    }
}

/// One element of an Access Credential's Assigned_Access_Rights array
/// (`BACnetAssignedAccessRights`, Clause 21).
///
/// On the wire the reference is framed in context tag `[0]` and the enable
/// flag follows as a context `[1]` BOOLEAN; the codec is
/// `bacnet_encoding::constructed::{encode_assigned_access_rights,
/// decode_assigned_access_rights}`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BACnetAssignedAccessRights {
    /// The Access Rights object granting these rights. Clause 12.35.18 marks
    /// an unused element with instance 4194303.
    pub assigned_access_rights: BACnetDeviceObjectReference,
    /// Whether the credential currently holds these rights.
    pub enable: bool,
}

/// An authentication factor value and its format (`BACnetAuthenticationFactor`,
/// Clause 21).
///
/// The three members go out as context tags `[0]` (the format type, an
/// ENUMERATED), `[1]` (the format class, an Unsigned) and `[2]` (the value
/// bytes, laid out as Annex P describes for the format).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BACnetAuthenticationFactor {
    /// The format of `value`.
    pub format_type: AuthenticationFactorType,
    /// The format class (Annex P).
    pub format_class: u32,
    /// The encoded factor, such as a card number.
    pub value: Vec<u8>,
}

/// One element of a Credential Data Input's Supported_Formats array
/// (`BACnetAuthenticationFactorFormat`, Clause 21; Clause 12.36.9).
///
/// The format type goes out as a context `[0]` ENUMERATED, and the two
/// vendor members, when present, as context `[1]` and `[2]` Unsigned16
/// values. A CUSTOM format names its vendor and that vendor's format number
/// in them; any other format leaves them out or sets them to zero.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BACnetAuthenticationFactorFormat {
    /// The format read.
    pub format_type: AuthenticationFactorType,
    /// For a CUSTOM format, the Vendor_Identifier of the company whose
    /// format it is.
    pub vendor_id: Option<u16>,
    /// That vendor's number for the CUSTOM format.
    pub vendor_format: Option<u16>,
}

impl BACnetAuthenticationFactorFormat {
    /// A standard format, with neither vendor member.
    pub const fn standard(format_type: AuthenticationFactorType) -> Self {
        Self {
            format_type,
            vendor_id: None,
            vendor_format: None,
        }
    }

    /// A CUSTOM format defined by vendor `vendor_id` as its format
    /// `vendor_format`.
    pub const fn custom(vendor_id: u16, vendor_format: u16) -> Self {
        Self {
            format_type: AuthenticationFactorType::CUSTOM,
            vendor_id: Some(vendor_id),
            vendor_format: Some(vendor_format),
        }
    }
}

/// One element of an Access Credential's Authentication_Factors array
/// (`BACnetCredentialAuthenticationFactor`, Clause 21).
///
/// The disable value goes out as a context `[0]` ENUMERATED; the factor
/// follows framed in context tag `[1]`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BACnetCredentialAuthenticationFactor {
    /// `NONE` when the factor may be used; any other value says why it
    /// can't (Clause 12.35.10).
    pub disable: AccessAuthenticationFactorDisable,
    /// The factor itself.
    pub authentication_factor: BACnetAuthenticationFactor,
}
