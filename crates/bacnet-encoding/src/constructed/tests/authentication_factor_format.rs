//! Credential Data Input Supported_Formats elements (#1169): golden bytes,
//! round trips and malformed input for `BACnetAuthenticationFactorFormat`.

use super::*;
use bacnet_types::constructed::BACnetAuthenticationFactorFormat;
use bacnet_types::enums::AuthenticationFactorType;

fn format(
    format_type: AuthenticationFactorType,
    vendor_id: Option<u16>,
    vendor_format: Option<u16>,
) -> BACnetAuthenticationFactorFormat {
    BACnetAuthenticationFactorFormat {
        format_type,
        vendor_id,
        vendor_format,
    }
}

#[test]
fn authentication_factor_format_golden_bytes_and_round_trip() {
    let cases: [(BACnetAuthenticationFactorFormat, &[u8]); 5] = [
        // format-type [0] WIEGAND26 alone.
        (
            BACnetAuthenticationFactorFormat::standard(AuthenticationFactorType::WIEGAND26),
            &[0x09, 0x08],
        ),
        // format-type [0] CUSTOM, vendor-id [1] 260, vendor-format [2] 7.
        (
            BACnetAuthenticationFactorFormat::custom(260, 7),
            &[0x09, 0x02, 0x1A, 0x01, 0x04, 0x29, 0x07],
        ),
        // A standard format carrying both vendor members as zero.
        (
            format(AuthenticationFactorType::ABA_TRACK2, Some(0), Some(0)),
            &[0x09, 0x07, 0x19, 0x00, 0x29, 0x00],
        ),
        // Only the vendor identifier, at the Unsigned16 ceiling.
        (
            format(AuthenticationFactorType::CUSTOM, Some(u16::MAX), None),
            &[0x09, 0x02, 0x1A, 0xFF, 0xFF],
        ),
        // Only the vendor's format.
        (
            format(AuthenticationFactorType::CUSTOM, None, Some(1)),
            &[0x09, 0x02, 0x29, 0x01],
        ),
    ];
    for (value, golden) in cases {
        let mut encoded = BytesMut::new();
        encode_authentication_factor_format(&mut encoded, &value);
        assert_eq!(&encoded[..], golden, "{value:?}");
        let (decoded, end) = decode_authentication_factor_format(golden, 0).unwrap();
        assert_eq!(decoded, value);
        assert_eq!(end, golden.len());
    }

    // The decoder keeps a format type outside the production for the
    // object to judge.
    let wide = format(AuthenticationFactorType::from_raw(99), None, None);
    let mut encoded = BytesMut::new();
    encode_authentication_factor_format(&mut encoded, &wide);
    assert_eq!(
        decode_authentication_factor_format(&encoded, 0).unwrap(),
        (wide, encoded.len())
    );
}

#[test]
fn authentication_factor_format_rejects_malformed_elements() {
    let malformed: [&[u8]; 6] = [
        // No format type.
        &[0x19, 0x00],
        // The format type under an application tag.
        &[0x91, 0x08],
        // A format type wider than 32 bits.
        &[0x0D, 0x05, 0x01, 0x00, 0x00, 0x00, 0x00],
        // A vendor identifier above 65535.
        &[0x09, 0x02, 0x1B, 0x01, 0x00, 0x00],
        // A vendor format above 65535.
        &[0x09, 0x02, 0x19, 0x01, 0x2B, 0x01, 0x00, 0x00],
        // The vendor identifier runs past the end of the data.
        &[0x09, 0x02, 0x1A, 0x01],
    ];
    for bytes in malformed {
        assert!(
            decode_authentication_factor_format(bytes, 0).is_err(),
            "{bytes:02X?} must not decode"
        );
    }
}

#[test]
fn authentication_factor_formats_decode_one_element_at_a_time() {
    // An array read whole is the elements back to back. A standard format
    // followed by a CUSTOM one: the optional members of the first must not
    // swallow the next element's format type.
    let elements = [
        BACnetAuthenticationFactorFormat::standard(AuthenticationFactorType::WIEGAND37),
        BACnetAuthenticationFactorFormat::custom(5, 9),
        BACnetAuthenticationFactorFormat::standard(AuthenticationFactorType::USER_PASSWORD),
    ];
    let mut array = BytesMut::new();
    for element in &elements {
        encode_authentication_factor_format(&mut array, element);
    }
    let mut offset = 0;
    for element in elements {
        let (decoded, next) = decode_authentication_factor_format(&array, offset).unwrap();
        assert_eq!(decoded, element);
        offset = next;
    }
    assert_eq!(offset, array.len());

    // Members out of order end the element early: the vendor format first
    // leaves the vendor identifier behind for the caller to refuse.
    let swapped: &[u8] = &[0x09, 0x02, 0x29, 0x07, 0x1A, 0x01, 0x04];
    let (decoded, end) = decode_authentication_factor_format(swapped, 0).unwrap();
    assert_eq!(
        decoded,
        format(AuthenticationFactorType::CUSTOM, None, Some(7))
    );
    assert_eq!(end, 4);
}
