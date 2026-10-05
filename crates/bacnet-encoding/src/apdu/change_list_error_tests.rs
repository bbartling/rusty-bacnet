//! ChangeList-Error (Clause 21), the error body of AddListElement and
//! RemoveListElement: `[0]` around the application-tagged class and code, then
//! the first failed element number as a `[1]` Unsigned. It replaces the plain
//! class/code pair rather than following it.

use super::*;

const SERVICES: [ConfirmedServiceChoice; 2] = [
    ConfirmedServiceChoice::ADD_LIST_ELEMENT,
    ConfirmedServiceChoice::REMOVE_LIST_ELEMENT,
];

/// SERVICES (5) / LIST_ELEMENT_NOT_FOUND (81), element 2: opening tag 0
/// (0x0E), two one-octet application Enumerated values (0x91), closing tag 0
/// (0x0F), and context tag 1 holding one octet (0x19).
const NOT_FOUND_AT_2: &[u8] = &[0x0E, 0x91, 5, 0x91, 81, 0x0F, 0x19, 2];

fn pdu(service_choice: ConfirmedServiceChoice, body: &'static [u8]) -> ErrorPdu {
    ErrorPdu {
        invoke_id: 21,
        service_choice,
        error_class: ErrorClass::SERVICES,
        error_code: ErrorCode::LIST_ELEMENT_NOT_FOUND,
        error_data: Bytes::from_static(body),
    }
}

fn encode_to_vec(apdu: &Apdu) -> Vec<u8> {
    let mut bytes = BytesMut::new();
    encode_apdu(&mut bytes, apdu).unwrap();
    bytes.to_vec()
}

#[test]
fn change_list_error_golden_vector_replaces_the_generic_pair() {
    for service in SERVICES {
        let pdu = pdu(service, NOT_FOUND_AT_2);
        let encoded = encode_to_vec(&Apdu::Error(pdu.clone()));
        assert_eq!(&encoded[..3], &[0x50, 21, service.to_raw()]);
        assert_eq!(&encoded[3..], NOT_FOUND_AT_2);
        assert_eq!(decode_apdu(Bytes::from(encoded)).unwrap(), Apdu::Error(pdu));
    }
}

#[test]
fn change_list_error_decodes_class_and_code_from_the_body() {
    // Element zero and a four-octet element number (0x1C) both qualify.
    for body in [
        &[0x0E, 0x91, 2, 0x91, 50, 0x0F, 0x19, 0][..],
        &[0x0E, 0x91, 2, 0x91, 50, 0x0F, 0x1C, 0xFF, 0xFF, 0xFF, 0xFF],
    ] {
        let mut wire = vec![0x50, 3, 8];
        wire.extend_from_slice(body);
        let Apdu::Error(decoded) = decode_apdu(Bytes::from(wire)).unwrap() else {
            panic!("expected an Error PDU");
        };
        assert_eq!(decoded.error_class, ErrorClass::PROPERTY);
        assert_eq!(decoded.error_code, ErrorCode::PROPERTY_IS_NOT_AN_ARRAY);
        assert_eq!(decoded.error_data.as_ref(), body);
    }
}

#[test]
fn legacy_plain_list_service_error_still_decodes_and_encodes() {
    for service in SERVICES {
        let pdu = ErrorPdu {
            invoke_id: 4,
            service_choice: service,
            error_class: ErrorClass::OBJECT,
            error_code: ErrorCode::UNKNOWN_OBJECT,
            error_data: Bytes::new(),
        };
        let encoded = encode_to_vec(&Apdu::Error(pdu.clone()));
        assert_eq!(&encoded[3..], &[0x91, 1, 0x91, 31]);
        assert_eq!(decode_apdu(Bytes::from(encoded)).unwrap(), Apdu::Error(pdu));
    }
}

#[test]
fn change_list_error_projection_must_match_body() {
    let mut pdu = pdu(ConfirmedServiceChoice::ADD_LIST_ELEMENT, NOT_FOUND_AT_2);
    pdu.error_code = ErrorCode::INVALID_DATA_TYPE;
    let mut encoded = BytesMut::new();
    assert!(encode_apdu(&mut encoded, &Apdu::Error(pdu)).is_err());
    assert!(encoded.is_empty());
}

#[test]
fn malformed_change_list_error_bodies_are_refused() {
    for (what, body) in [
        (
            "missing element number",
            &[0x0E, 0x91, 5, 0x91, 81, 0x0F][..],
        ),
        (
            "element number in an opening tag",
            &[0x0E, 0x91, 5, 0x91, 81, 0x0F, 0x1E, 0x21, 2, 0x1F],
        ),
        (
            "element number under context tag 2",
            &[0x0E, 0x91, 5, 0x91, 81, 0x0F, 0x29, 2],
        ),
        (
            "element number past u32",
            &[0x0E, 0x91, 5, 0x91, 81, 0x0F, 0x1D, 5, 1, 0, 0, 0, 0],
        ),
        (
            "empty element number",
            &[0x0E, 0x91, 5, 0x91, 81, 0x0F, 0x18],
        ),
        (
            "truncated element number",
            &[0x0E, 0x91, 5, 0x91, 81, 0x0F, 0x1A, 2],
        ),
        (
            "trailing content",
            &[0x0E, 0x91, 5, 0x91, 81, 0x0F, 0x19, 2, 0x00],
        ),
        ("one enumerated in [0]", &[0x0E, 0x91, 5, 0x0F, 0x19, 2]),
        (
            "three enumerated in [0]",
            &[0x0E, 0x91, 5, 0x91, 81, 0x91, 1, 0x0F, 0x19, 2],
        ),
        ("unclosed [0]", &[0x0E, 0x91, 5, 0x91, 81, 0x19, 2]),
    ] {
        for service in SERVICES {
            let mut wire = vec![0x50, 1, service.to_raw()];
            wire.extend_from_slice(body);
            assert!(
                decode_apdu(Bytes::from(wire)).is_err(),
                "{what} decoded for {service:?}"
            );
        }
    }
}

#[test]
fn change_list_body_is_formal_only_for_the_list_services() {
    // Under ReadProperty the bytes after the generic pair stay opaque data.
    let pdu = ErrorPdu {
        invoke_id: 6,
        service_choice: ConfirmedServiceChoice::READ_PROPERTY,
        error_class: ErrorClass::SERVICES,
        error_code: ErrorCode::LIST_ELEMENT_NOT_FOUND,
        error_data: Bytes::from_static(NOT_FOUND_AT_2),
    };
    let encoded = encode_to_vec(&Apdu::Error(pdu.clone()));
    assert_eq!(&encoded[3..7], &[0x91, 5, 0x91, 81]);
    assert_eq!(&encoded[7..], NOT_FOUND_AT_2);
    assert_eq!(decode_apdu(Bytes::from(encoded)).unwrap(), Apdu::Error(pdu));
    // A WPM body needs its [1] frame, so the ChangeList shape is malformed there.
    let mut wire = vec![0x50, 1, 16];
    wire.extend_from_slice(NOT_FOUND_AT_2);
    assert!(decode_apdu(Bytes::from(wire)).is_err());
}
