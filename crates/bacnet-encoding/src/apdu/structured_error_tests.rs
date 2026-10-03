//! CreateObject-Error, SubscribeCOVPropertyMultiple-Error,
//! ConfirmedPrivateTransfer-Error and VTClose-Error (Clause 21): each body
//! replaces the plain class/code pair, so the APDU codec must recognize it by
//! service in both directions instead of failing to decode a conformant
//! peer's error.

use super::*;

const CREATE_OBJECT: ConfirmedServiceChoice = ConfirmedServiceChoice::CREATE_OBJECT;
const SCPM: ConfirmedServiceChoice = ConfirmedServiceChoice::SUBSCRIBE_COV_PROPERTY_MULTIPLE;
const PRIVATE_TRANSFER: ConfirmedServiceChoice = ConfirmedServiceChoice::CONFIRMED_PRIVATE_TRANSFER;
const VT_CLOSE: ConfirmedServiceChoice = ConfirmedServiceChoice::VT_CLOSE;

/// PROPERTY (2) / WRITE_ACCESS_DENIED (40) at initial value 3: `[0]` around
/// two one-octet application Enumerated values (0x91), then context tag 1
/// holding one octet (0x19).
const CREATE_AT_3: &[u8] = &[0x0E, 0x91, 2, 0x91, 40, 0x0F, 0x19, 3];
/// SERVICES (5) / VALUE_OUT_OF_RANGE (37), the general `[0]` choice.
const SCPM_GENERAL: &[u8] = &[0x0E, 0x91, 5, 0x91, 37, 0x0F];
/// The `[1]` choice: object (ANALOG_VALUE, 7) under context tag 0 (0x0C,
/// four octets), property reference PRESENT_VALUE (85) in `[1]`, and
/// PROPERTY (2) / NOT_COV_PROPERTY (44) in `[2]`.
const SCPM_SUBSCRIPTION: &[u8] = &[
    0x1E, 0x0C, 0x00, 0x80, 0x00, 0x07, 0x1E, 0x09, 85, 0x1F, 0x2E, 0x91, 2, 0x91, 44, 0x2F, 0x1F,
];
/// The same with array index 8 (0x19 0x08) in the property reference.
const SCPM_INDEXED: &[u8] = &[
    0x1E, 0x0C, 0x00, 0x80, 0x00, 0x07, 0x1E, 0x09, 85, 0x19, 8, 0x1F, 0x2E, 0x91, 2, 0x91, 44,
    0x2F, 0x1F,
];
/// SERVICES (5) / OPTIONAL_FUNCTIONALITY_NOT_SUPPORTED (45), vendor 555 in
/// two octets (0x1A), service 7 (0x29), error parameters `[3]` holding
/// application Unsigned 1.
const PRIVATE_WITH_PARAMETERS: &[u8] = &[
    0x0E, 0x91, 5, 0x91, 45, 0x0F, 0x1A, 0x02, 0x2B, 0x29, 7, 0x3E, 0x21, 1, 0x3F,
];
const PRIVATE_WITHOUT_PARAMETERS: &[u8] =
    &[0x0E, 0x91, 5, 0x91, 45, 0x0F, 0x1A, 0x02, 0x2B, 0x29, 7];
/// SERVICES (5) / VT_SESSION_TERMINATION_FAILURE (39) with sessions 1 and 4
/// as application Unsigned (0x21) in `[1]`.
const VT_CLOSE_WITH_LIST: &[u8] = &[0x0E, 0x91, 5, 0x91, 39, 0x0F, 0x1E, 0x21, 1, 0x21, 4, 0x1F];
/// SERVICES (5) / UNKNOWN_VT_SESSION (35), list omitted.
const VT_CLOSE_WITHOUT_LIST: &[u8] = &[0x0E, 0x91, 5, 0x91, 35, 0x0F];

/// Every golden vector with the class and code its body carries.
const GOLDEN: [(ConfirmedServiceChoice, ErrorClass, ErrorCode, &[u8]); 8] = [
    (
        CREATE_OBJECT,
        ErrorClass::PROPERTY,
        ErrorCode::WRITE_ACCESS_DENIED,
        CREATE_AT_3,
    ),
    (
        SCPM,
        ErrorClass::SERVICES,
        ErrorCode::VALUE_OUT_OF_RANGE,
        SCPM_GENERAL,
    ),
    (
        SCPM,
        ErrorClass::PROPERTY,
        ErrorCode::NOT_COV_PROPERTY,
        SCPM_SUBSCRIPTION,
    ),
    (
        SCPM,
        ErrorClass::PROPERTY,
        ErrorCode::NOT_COV_PROPERTY,
        SCPM_INDEXED,
    ),
    (
        PRIVATE_TRANSFER,
        ErrorClass::SERVICES,
        ErrorCode::OPTIONAL_FUNCTIONALITY_NOT_SUPPORTED,
        PRIVATE_WITH_PARAMETERS,
    ),
    (
        PRIVATE_TRANSFER,
        ErrorClass::SERVICES,
        ErrorCode::OPTIONAL_FUNCTIONALITY_NOT_SUPPORTED,
        PRIVATE_WITHOUT_PARAMETERS,
    ),
    (
        VT_CLOSE,
        ErrorClass::SERVICES,
        ErrorCode::VT_SESSION_TERMINATION_FAILURE,
        VT_CLOSE_WITH_LIST,
    ),
    (
        VT_CLOSE,
        ErrorClass::SERVICES,
        ErrorCode::UNKNOWN_VT_SESSION,
        VT_CLOSE_WITHOUT_LIST,
    ),
];

fn encode_to_vec(apdu: &Apdu) -> Vec<u8> {
    let mut bytes = BytesMut::new();
    encode_apdu(&mut bytes, apdu).unwrap();
    bytes.to_vec()
}

fn wire(service: ConfirmedServiceChoice, body: &[u8]) -> Bytes {
    let mut wire = vec![0x50, 9, service.to_raw()];
    wire.extend_from_slice(body);
    Bytes::from(wire)
}

#[test]
fn structured_error_golden_vectors_replace_the_generic_pair() {
    for (service, error_class, error_code, body) in GOLDEN {
        let pdu = ErrorPdu {
            invoke_id: 9,
            service_choice: service,
            error_class,
            error_code,
            error_data: Bytes::copy_from_slice(body),
        };
        let encoded = encode_to_vec(&Apdu::Error(pdu.clone()));
        assert_eq!(encoded, wire(service, body), "{service:?} {body:02x?}");
        assert_eq!(
            decode_apdu(Bytes::from(encoded)).unwrap(),
            Apdu::Error(pdu),
            "{service:?} {body:02x?}"
        );
    }
}

#[test]
fn structured_error_projection_must_match_body() {
    for (service, error_class, _, body) in GOLDEN {
        let pdu = ErrorPdu {
            invoke_id: 9,
            service_choice: service,
            error_class,
            error_code: ErrorCode::UNKNOWN_OBJECT,
            error_data: Bytes::copy_from_slice(body),
        };
        let mut encoded = BytesMut::new();
        assert!(
            encode_apdu(&mut encoded, &Apdu::Error(pdu)).is_err(),
            "{service:?} {body:02x?}"
        );
        assert!(encoded.is_empty());
    }
}

#[test]
fn legacy_plain_errors_still_decode_and_encode() {
    for service in [CREATE_OBJECT, SCPM, PRIVATE_TRANSFER, VT_CLOSE] {
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
fn malformed_structured_error_bodies_are_refused() {
    let cases: &[(ConfirmedServiceChoice, &str, &[u8])] = &[
        (
            CREATE_OBJECT,
            "missing element number",
            &[0x0E, 0x91, 2, 0x91, 40, 0x0F],
        ),
        (
            CREATE_OBJECT,
            "element number past u32",
            &[0x0E, 0x91, 2, 0x91, 40, 0x0F, 0x1D, 5, 1, 0, 0, 0, 0],
        ),
        (
            CREATE_OBJECT,
            "trailing content",
            &[0x0E, 0x91, 2, 0x91, 40, 0x0F, 0x19, 3, 0x00],
        ),
        (
            SCPM,
            "general choice with trailing content",
            &[0x0E, 0x91, 5, 0x91, 37, 0x0F, 0x19, 1],
        ),
        (
            SCPM,
            "subscription without its error",
            &[
                0x1E, 0x0C, 0x00, 0x80, 0x00, 0x07, 0x1E, 0x09, 85, 0x1F, 0x1F,
            ],
        ),
        (
            SCPM,
            "subscription object in three octets",
            &[
                0x1E, 0x0B, 0x80, 0x00, 0x07, 0x1E, 0x09, 85, 0x1F, 0x2E, 0x91, 2, 0x91, 44, 0x2F,
                0x1F,
            ],
        ),
        (
            SCPM,
            "subscription property reference not framed",
            &[
                0x1E, 0x0C, 0x00, 0x80, 0x00, 0x07, 0x19, 85, 0x2E, 0x91, 2, 0x91, 44, 0x2F, 0x1F,
            ],
        ),
        (
            SCPM,
            "subscription property reference with two indexes",
            &[
                0x1E, 0x0C, 0x00, 0x80, 0x00, 0x07, 0x1E, 0x09, 85, 0x19, 1, 0x19, 2, 0x1F, 0x2E,
                0x91, 2, 0x91, 44, 0x2F, 0x1F,
            ],
        ),
        (
            SCPM,
            "subscription error under [0]",
            &[
                0x1E, 0x0C, 0x00, 0x80, 0x00, 0x07, 0x1E, 0x09, 85, 0x1F, 0x0E, 0x91, 2, 0x91, 44,
                0x0F, 0x1F,
            ],
        ),
        (
            SCPM,
            "unclosed subscription",
            &[
                0x1E, 0x0C, 0x00, 0x80, 0x00, 0x07, 0x1E, 0x09, 85, 0x1F, 0x2E, 0x91, 2, 0x91, 44,
                0x2F,
            ],
        ),
        (
            PRIVATE_TRANSFER,
            "missing service number",
            &[0x0E, 0x91, 5, 0x91, 45, 0x0F, 0x1A, 0x02, 0x2B],
        ),
        (
            PRIVATE_TRANSFER,
            "members out of order",
            &[0x0E, 0x91, 5, 0x91, 45, 0x0F, 0x29, 7, 0x1A, 0x02, 0x2B],
        ),
        (
            PRIVATE_TRANSFER,
            "unclosed error parameters",
            &[
                0x0E, 0x91, 5, 0x91, 45, 0x0F, 0x1A, 0x02, 0x2B, 0x29, 7, 0x3E, 0x21, 1,
            ],
        ),
        (
            PRIVATE_TRANSFER,
            "error parameters not framed",
            &[
                0x0E, 0x91, 5, 0x91, 45, 0x0F, 0x1A, 0x02, 0x2B, 0x29, 7, 0x39, 1,
            ],
        ),
        (
            PRIVATE_TRANSFER,
            "trailing content after the parameters",
            &[
                0x0E, 0x91, 5, 0x91, 45, 0x0F, 0x1A, 0x02, 0x2B, 0x29, 7, 0x3E, 0x3F, 0x00,
            ],
        ),
        (
            VT_CLOSE,
            "session identifier past Unsigned8",
            &[0x0E, 0x91, 5, 0x91, 39, 0x0F, 0x1E, 0x22, 1, 0, 0x1F],
        ),
        (
            VT_CLOSE,
            "session identifier context tagged",
            &[0x0E, 0x91, 5, 0x91, 39, 0x0F, 0x1E, 0x09, 1, 0x1F],
        ),
        (
            VT_CLOSE,
            "unframed session identifiers",
            &[0x0E, 0x91, 5, 0x91, 39, 0x0F, 0x21, 1],
        ),
        (
            VT_CLOSE,
            "unclosed list",
            &[0x0E, 0x91, 5, 0x91, 39, 0x0F, 0x1E, 0x21, 1],
        ),
        (
            VT_CLOSE,
            "one enumerated in [0]",
            &[0x0E, 0x91, 5, 0x0F, 0x1E, 0x21, 1, 0x1F],
        ),
    ];
    for (service, what, body) in cases {
        assert!(
            decode_apdu(wire(*service, body)).is_err(),
            "{what} decoded for {service:?}"
        );
    }
    // The CHOICE takes one alternative, never both.
    let both = [SCPM_GENERAL, SCPM_SUBSCRIPTION].concat();
    assert!(decode_apdu(wire(SCPM, &both)).is_err());
}

#[test]
fn structured_bodies_are_formal_only_for_their_services() {
    // Under ReadProperty the bytes after the generic pair stay opaque data.
    for (_, _, _, body) in GOLDEN {
        let pdu = ErrorPdu {
            invoke_id: 6,
            service_choice: ConfirmedServiceChoice::READ_PROPERTY,
            error_class: ErrorClass::SERVICES,
            error_code: ErrorCode::OTHER,
            error_data: Bytes::copy_from_slice(body),
        };
        let encoded = encode_to_vec(&Apdu::Error(pdu.clone()));
        assert_eq!(&encoded[3..7], &[0x91, 5, 0x91, 0]);
        assert_eq!(&encoded[7..], body);
        assert_eq!(decode_apdu(Bytes::from(encoded)).unwrap(), Apdu::Error(pdu));
    }
    // The `[1]` choice opens a body only for SubscribeCOVPropertyMultiple.
    let mut wire = vec![0x50, 1, CREATE_OBJECT.to_raw()];
    wire.extend_from_slice(SCPM_SUBSCRIPTION);
    assert!(decode_apdu(Bytes::from(wire)).is_err());
}

#[test]
fn formal_members_cut_short_are_a_short_buffer() {
    // An element number, a vendor identifier and a service number that each
    // say two octets and hold one; need and have count from the body.
    for (service, body, need) in [
        (
            CREATE_OBJECT,
            &[0x0E, 0x91, 2, 0x91, 40, 0x0F, 0x1A, 3][..],
            9,
        ),
        (
            ConfirmedServiceChoice::REMOVE_LIST_ELEMENT,
            &[0x0E, 0x91, 5, 0x91, 81, 0x0F, 0x1A, 2],
            9,
        ),
        (
            PRIVATE_TRANSFER,
            &[0x0E, 0x91, 5, 0x91, 45, 0x0F, 0x1A, 0x02],
            9,
        ),
        (
            PRIVATE_TRANSFER,
            &[0x0E, 0x91, 5, 0x91, 45, 0x0F, 0x1A, 0x02, 0x2B, 0x2A, 7],
            12,
        ),
    ] {
        match decode_apdu(wire(service, body)) {
            Err(Error::BufferTooShort { need: n, have }) => {
                assert_eq!((n, have), (need, body.len()), "{service:?} {body:02X?}");
            }
            other => panic!("expected a short buffer for {service:?} {body:02X?}, got {other:?}"),
        }
    }
}
