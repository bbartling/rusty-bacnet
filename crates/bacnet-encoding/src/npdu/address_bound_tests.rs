//! Wire-level tests for the DADR/SADR length bound (#1141): a DLEN or SLEN
//! past [`NpduAddress::MAX_MAC_LEN`] is refused in both directions, the
//! lengths up to it still work, and both addresses behave the same way.

use super::*;

const FIELDS: [NpduAddressField; 2] = [NpduAddressField::Destination, NpduAddressField::Source];
const DNET: u16 = 2000;
const SNET: u16 = 3000;
const APDU: [u8; 2] = [0x10, 0x08];

/// Hand-built NPDU wire bytes (the encoder refuses the lengths under test).
/// The `field` address announces `length` octets but holds only `present` of
/// them; the other address, when the frame has one, is a valid 1-octet MAC.
/// A source-field frame also carries a destination when `routed` is set.
fn frame(field: NpduAddressField, length: u8, present: u8, routed: bool) -> Vec<u8> {
    let address = |first: u8| (0..present).map(move |i| first.wrapping_add(i));
    let mut out = vec![BACNET_PROTOCOL_VERSION];
    match field {
        NpduAddressField::Destination => {
            out.push(0x20);
            out.extend_from_slice(&DNET.to_be_bytes());
            out.push(length);
            out.extend(address(0xD0));
        }
        NpduAddressField::Source => {
            if routed {
                out.push(0x28);
                out.extend_from_slice(&DNET.to_be_bytes());
                out.extend_from_slice(&[1, 0xD0]);
            } else {
                out.push(0x08);
            }
            out.extend_from_slice(&SNET.to_be_bytes());
            out.push(length);
            out.extend(address(0x50));
        }
    }
    if field == NpduAddressField::Destination || routed {
        out.push(255); // hop count
    }
    out.extend_from_slice(&APDU);
    out
}

/// A complete frame whose `field` address is `length` octets long.
fn full(field: NpduAddressField, length: u8) -> Vec<u8> {
    frame(field, length, length, false)
}

fn decode(bytes: Vec<u8>) -> Result<Npdu, NpduDecodeError> {
    decode_npdu(Bytes::from(bytes))
}

fn expected_dnet(field: NpduAddressField) -> Option<u16> {
    (field == NpduAddressField::Destination).then_some(DNET)
}

fn address_of(npdu: &Npdu, field: NpduAddressField) -> &NpduAddress {
    match field {
        NpduAddressField::Destination => npdu.destination.as_ref(),
        NpduAddressField::Source => npdu.source.as_ref(),
    }
    .expect("decoded NPDU carries the address under test")
}

#[test]
fn npdu_address_bound_matches_the_recipient_bound() {
    assert_eq!(NpduAddress::MAX_MAC_LEN, 18);
    assert_eq!(NpduAddress::MAX_MAC_LEN, BACnetAddress::MAX_MAC_LEN);
}

#[test]
fn over_long_address_length_is_refused_for_either_field() {
    for field in FIELDS {
        for length in [19, 64, 255] {
            match decode(full(field, length)) {
                Err(NpduDecodeError::AddressTooLong {
                    field: refused,
                    length: reported,
                    dnet,
                }) => {
                    assert_eq!(refused, field);
                    assert_eq!(reported, length);
                    assert_eq!(dnet, expected_dnet(field), "{field} {length}");
                }
                other => panic!("{field} length {length}: expected AddressTooLong, got {other:?}"),
            }
        }
    }
}

#[test]
fn over_long_length_is_refused_before_the_address_is_read() {
    // Only two of the announced octets are present: the length alone decides,
    // so this is AddressTooLong rather than a truncated address.
    for field in FIELDS {
        let refused = decode(frame(field, 255, 2, false)).unwrap_err();
        assert!(
            matches!(refused, NpduDecodeError::AddressTooLong { length: 255, .. }),
            "{field}: {refused:?}"
        );
        // A length within the bound but past the frame is a truncation.
        let truncated = decode(frame(field, 18, 2, false)).unwrap_err();
        assert!(
            matches!(truncated, NpduDecodeError::Malformed(_)),
            "{field}: {truncated:?}"
        );
    }
}

#[test]
fn boundary_address_lengths_decode_and_round_trip_for_either_field() {
    for field in FIELDS {
        for length in [1, 6, 18] {
            let wire = full(field, length);
            let npdu = decode(wire.clone()).unwrap_or_else(|e| panic!("{field} {length}: {e}"));
            assert_eq!(
                address_of(&npdu, field).mac_address.len(),
                usize::from(length)
            );
            assert_eq!(npdu.payload, APDU[..]);
            let mut again = BytesMut::new();
            encode_npdu(&mut again, &npdu).unwrap();
            assert_eq!(
                again.as_ref(),
                wire,
                "{field} {length} re-encodes unchanged"
            );
        }
    }
}

#[test]
fn source_refusal_reports_the_npdu_dnet() {
    let refused = decode(frame(NpduAddressField::Source, 19, 19, true)).unwrap_err();
    assert!(
        matches!(
            refused,
            NpduDecodeError::AddressTooLong {
                field: NpduAddressField::Source,
                length: 19,
                dnet: Some(DNET),
            }
        ),
        "{refused:?}"
    );
    let accepted = decode(frame(NpduAddressField::Source, 18, 18, true)).unwrap();
    assert_eq!(accepted.destination.unwrap().network, DNET);
    assert_eq!(accepted.source.unwrap().mac_address.len(), 18);
}

#[test]
fn address_too_long_reads_as_out_of_range() {
    for field in FIELDS {
        let refused = decode(full(field, 19)).unwrap_err();
        let text = refused.to_string();
        assert!(
            text.contains(&format!("{}=19", field.length_octet())),
            "{text}"
        );
        assert!(matches!(Error::from(refused), Error::OutOfRange(_)));
    }
    let malformed = decode(vec![BACNET_PROTOCOL_VERSION]).unwrap_err();
    assert!(matches!(
        Error::from(malformed),
        Error::BufferTooShort { .. }
    ));
}

#[test]
fn encoder_refuses_an_address_past_the_bound_for_either_field() {
    for field in FIELDS {
        for length in [NpduAddress::MAX_MAC_LEN, NpduAddress::MAX_MAC_LEN + 1] {
            let address = NpduAddress {
                network: if field == NpduAddressField::Destination {
                    DNET
                } else {
                    SNET
                },
                mac_address: MacAddr::from_slice(&vec![0x42; length]),
            };
            let npdu = match field {
                NpduAddressField::Destination => Npdu {
                    destination: Some(address),
                    ..Npdu::default()
                },
                NpduAddressField::Source => Npdu {
                    source: Some(address),
                    ..Npdu::default()
                },
            };
            let result = encode_npdu(&mut BytesMut::new(), &npdu);
            if length > NpduAddress::MAX_MAC_LEN {
                let text = result.unwrap_err().to_string();
                assert!(
                    text.contains(&format!("{field} address of 19 octets")),
                    "{text}"
                );
            } else {
                result.unwrap_or_else(|e| panic!("{field} {length}: {e}"));
            }
        }
    }
}
