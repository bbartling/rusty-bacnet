//! Constructed values served by the Access Credential object (Clause 12.35)
//! and the Credential Data Input object (Clause 12.36).

#[cfg(not(feature = "std"))]
use alloc::vec::Vec;

use super::BACnetDeviceObjectReference;
use crate::enums::{AccessAuthenticationFactorDisable, AuthenticationFactorType};

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
