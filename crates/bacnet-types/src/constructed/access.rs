//! Constructed values served by the Access Credential object (Clause 12.35).

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
