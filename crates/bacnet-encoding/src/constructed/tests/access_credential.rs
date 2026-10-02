//! Access Credential array elements (#1073): golden bytes, round trips and
//! malformed input for `BACnetAssignedAccessRights`,
//! `BACnetAuthenticationFactor` and `BACnetCredentialAuthenticationFactor`.

use super::*;
use bacnet_types::constructed::{
    BACnetAssignedAccessRights, BACnetAuthenticationFactor, BACnetCredentialAuthenticationFactor,
    BACnetDeviceObjectReference,
};
use bacnet_types::enums::{AccessAuthenticationFactorDisable, AuthenticationFactorType};

fn rights(device: Option<u32>, instance: u32, enable: bool) -> BACnetAssignedAccessRights {
    BACnetAssignedAccessRights {
        assigned_access_rights: BACnetDeviceObjectReference {
            device_identifier: device
                .map(|instance| ObjectIdentifier::new(ObjectType::DEVICE, instance).unwrap()),
            object_identifier: ObjectIdentifier::new(ObjectType::ACCESS_RIGHTS, instance).unwrap(),
        },
        enable,
    }
}

fn factor(
    disable: AccessAuthenticationFactorDisable,
    value: &[u8],
) -> BACnetCredentialAuthenticationFactor {
    BACnetCredentialAuthenticationFactor {
        disable,
        authentication_factor: BACnetAuthenticationFactor {
            format_type: AuthenticationFactorType::WIEGAND26,
            format_class: 0,
            value: value.to_vec(),
        },
    }
}

#[test]
fn assigned_access_rights_golden_bytes_and_round_trip() {
    // Access Rights 5 is (34 << 22) | 5; Device 99 is (8 << 22) | 99.
    let cases: [(BACnetAssignedAccessRights, &[u8]); 2] = [
        (
            rights(None, 5, true),
            &[0x0E, 0x1C, 0x08, 0x80, 0x00, 0x05, 0x0F, 0x19, 0x01],
        ),
        (
            rights(Some(99), 5, false),
            &[
                0x0E, 0x0C, 0x02, 0x00, 0x00, 0x63, 0x1C, 0x08, 0x80, 0x00, 0x05, 0x0F, 0x19, 0x00,
            ],
        ),
    ];
    for (value, golden) in cases {
        let mut encoded = BytesMut::new();
        encode_assigned_access_rights(&mut encoded, &value);
        assert_eq!(&encoded[..], golden);
        let (decoded, end) = decode_assigned_access_rights(golden, 0).unwrap();
        assert_eq!(decoded, value);
        assert_eq!(end, golden.len());
    }
}

#[test]
fn assigned_access_rights_rejects_malformed_elements() {
    let malformed: [&[u8]; 7] = [
        // The reference without its frame.
        &[0x1C, 0x08, 0x80, 0x00, 0x05, 0x19, 0x01],
        // No closing tag 0.
        &[0x0E, 0x1C, 0x08, 0x80, 0x00, 0x05, 0x19, 0x01],
        // An empty frame: the object identifier is required.
        &[0x0E, 0x0F, 0x19, 0x01],
        // No enable flag.
        &[0x0E, 0x1C, 0x08, 0x80, 0x00, 0x05, 0x0F],
        // A BOOLEAN must hold 0 or 1.
        &[0x0E, 0x1C, 0x08, 0x80, 0x00, 0x05, 0x0F, 0x19, 0x02],
        // The enable flag under the wrong tag.
        &[0x0E, 0x1C, 0x08, 0x80, 0x00, 0x05, 0x0F, 0x29, 0x01],
        // Truncated inside the object identifier.
        &[0x0E, 0x1C, 0x08, 0x80],
    ];
    for bytes in malformed {
        assert!(
            decode_assigned_access_rights(bytes, 0).is_err(),
            "{bytes:02X?} must not decode"
        );
    }
}

#[test]
fn credential_authentication_factor_golden_bytes_and_round_trip() {
    let value = factor(AccessAuthenticationFactorDisable::NONE, &[0x12, 0x34, 0x56]);
    let golden: &[u8] = &[
        0x09, 0x00, // disable [0] NONE
        0x1E, // authentication-factor [1]
        0x09, 0x08, // format-type [0] WIEGAND26
        0x19, 0x00, // format-class [1] 0
        0x2B, 0x12, 0x34, 0x56, // value [2]
        0x1F,
    ];
    let mut encoded = BytesMut::new();
    encode_credential_authentication_factor(&mut encoded, &value);
    assert_eq!(&encoded[..], golden);
    let (decoded, end) = decode_credential_authentication_factor(golden, 0).unwrap();
    assert_eq!(decoded, value);
    assert_eq!(end, golden.len());

    // The embedded factor decodes on its own from inside the frame.
    let (inner, inner_end) = decode_authentication_factor(golden, 3).unwrap();
    assert_eq!(inner, value.authentication_factor);
    assert_eq!(inner_end, golden.len() - 1);

    // A vendor disable value, a wide format class and an empty value all
    // round-trip; the decoder keeps values for the object to judge.
    let mut wide = factor(AccessAuthenticationFactorDisable::from_raw(700), &[]);
    wide.authentication_factor.format_class = u32::MAX;
    wide.authentication_factor.format_type = AuthenticationFactorType::from_raw(99);
    let mut encoded = BytesMut::new();
    encode_credential_authentication_factor(&mut encoded, &wide);
    let (decoded, end) = decode_credential_authentication_factor(&encoded, 0).unwrap();
    assert_eq!(decoded, wide);
    assert_eq!(end, encoded.len());
}

#[test]
fn credential_authentication_factor_rejects_malformed_elements() {
    let malformed: [&[u8]; 8] = [
        // No disable member.
        &[0x1E, 0x09, 0x08, 0x19, 0x00, 0x28, 0x1F],
        // No frame around the factor.
        &[0x09, 0x00, 0x09, 0x08, 0x19, 0x00, 0x28],
        // No closing tag 1.
        &[0x09, 0x00, 0x1E, 0x09, 0x08, 0x19, 0x00, 0x28],
        // Format class missing.
        &[0x09, 0x00, 0x1E, 0x09, 0x08, 0x28, 0x1F],
        // Members out of order.
        &[0x09, 0x00, 0x1E, 0x19, 0x00, 0x09, 0x08, 0x28, 0x1F],
        // Something after the factor inside the frame.
        &[
            0x09, 0x00, 0x1E, 0x09, 0x08, 0x19, 0x00, 0x28, 0x21, 0x01, 0x1F,
        ],
        // A format type wider than 32 bits.
        &[
            0x09, 0x00, 0x1E, 0x0D, 0x05, 0x01, 0x00, 0x00, 0x00, 0x00, 0x19, 0x00, 0x28, 0x1F,
        ],
        // The value runs past the end of the data.
        &[0x09, 0x00, 0x1E, 0x09, 0x08, 0x19, 0x00, 0x2B, 0x12],
    ];
    for bytes in malformed {
        assert!(
            decode_credential_authentication_factor(bytes, 0).is_err(),
            "{bytes:02X?} must not decode"
        );
    }
}

#[test]
fn access_credential_elements_leave_trailing_bytes_to_the_caller() {
    let mut array = BytesMut::new();
    encode_assigned_access_rights(&mut array, &rights(None, 1, true));
    encode_assigned_access_rights(&mut array, &rights(Some(7), 2, false));
    let (first, next) = decode_assigned_access_rights(&array, 0).unwrap();
    let (second, end) = decode_assigned_access_rights(&array, next).unwrap();
    assert_eq!(first, rights(None, 1, true));
    assert_eq!(second, rights(Some(7), 2, false));
    assert_eq!(end, array.len());

    let mut array = BytesMut::new();
    encode_credential_authentication_factor(
        &mut array,
        &factor(AccessAuthenticationFactorDisable::NONE, &[1]),
    );
    let first_end = array.len();
    encode_credential_authentication_factor(
        &mut array,
        &factor(AccessAuthenticationFactorDisable::DISABLED_LOST, &[2, 3]),
    );
    let (_, next) = decode_credential_authentication_factor(&array, 0).unwrap();
    assert_eq!(next, first_end);
    let (second, end) = decode_credential_authentication_factor(&array, next).unwrap();
    assert_eq!(
        second.disable,
        AccessAuthenticationFactorDisable::DISABLED_LOST
    );
    assert_eq!(end, array.len());
}
