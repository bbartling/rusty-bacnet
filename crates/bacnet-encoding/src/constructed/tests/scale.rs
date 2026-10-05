//! `BACnetScale` CHOICE and `BACnetPrescale` SEQUENCE vectors (Clause 21).
use super::*;
use bacnet_types::constructed::{BACnetPrescale, BACnetScale};

fn encode_one_scale(value: &BACnetScale) -> Vec<u8> {
    let mut buf = BytesMut::new();
    encode_scale(&mut buf, value);
    buf.to_vec()
}

fn encode_one_prescale(value: &BACnetPrescale) -> Vec<u8> {
    let mut buf = BytesMut::new();
    encode_prescale(&mut buf, value);
    buf.to_vec()
}

fn prescale(multiplier: u32, modulo_divide: u32) -> BACnetPrescale {
    BACnetPrescale {
        multiplier,
        modulo_divide,
    }
}

/// Bytes written out by hand from the context tags, not produced by the
/// codec: float-scale `[0]` holds a four-octet REAL, integer-scale `[1]` a
/// two's-complement INTEGER in the fewest octets.
fn scale_vectors() -> Vec<(BACnetScale, Vec<u8>)> {
    vec![
        (
            BACnetScale::FloatScale(1.0),
            vec![0x0C, 0x3F, 0x80, 0x00, 0x00],
        ),
        (
            BACnetScale::FloatScale(2.5),
            vec![0x0C, 0x40, 0x20, 0x00, 0x00],
        ),
        (BACnetScale::IntegerScale(0), vec![0x19, 0x00]),
        (BACnetScale::IntegerScale(-3), vec![0x19, 0xFD]),
        (BACnetScale::IntegerScale(300), vec![0x1A, 0x01, 0x2C]),
        (
            BACnetScale::IntegerScale(i32::MIN),
            vec![0x1C, 0x80, 0x00, 0x00, 0x00],
        ),
    ]
}

/// The multiplier under `[0]`, then the modulo divide under `[1]`, each an
/// Unsigned in the fewest octets.
fn prescale_vectors() -> Vec<(BACnetPrescale, Vec<u8>)> {
    vec![
        (prescale(5, 100), vec![0x09, 0x05, 0x19, 0x64]),
        (prescale(1, 1), vec![0x09, 0x01, 0x19, 0x01]),
        (
            prescale(0, u32::MAX),
            vec![0x09, 0x00, 0x1C, 0xFF, 0xFF, 0xFF, 0xFF],
        ),
    ]
}

#[test]
fn scale_and_prescale_golden_vectors_round_trip() {
    for (value, bytes) in scale_vectors() {
        assert_eq!(encode_one_scale(&value), bytes, "{value:?}");
        assert_eq!(
            decode_scale(&bytes, 0).unwrap(),
            (value, bytes.len()),
            "{bytes:02X?}"
        );
    }
    for (value, bytes) in prescale_vectors() {
        assert_eq!(encode_one_prescale(&value), bytes, "{value:?}");
        assert_eq!(
            decode_prescale(&bytes, 0).unwrap(),
            (value, bytes.len()),
            "{bytes:02X?}"
        );
    }
}

#[test]
fn scale_and_prescale_decode_at_an_offset_and_leave_what_follows() {
    let data = [0xAA, 0x19, 0x02, 0x0C, 0x40, 0x20, 0x00, 0x00, 0x21];
    let (first, next) = decode_scale(&data, 1).unwrap();
    assert_eq!((first, next), (BACnetScale::IntegerScale(2), 3));
    assert_eq!(
        decode_scale(&data, next).unwrap(),
        (BACnetScale::FloatScale(2.5), 8)
    );
    let data = [0xAA, 0x09, 0x05, 0x19, 0x64, 0x21];
    assert_eq!(decode_prescale(&data, 1).unwrap(), (prescale(5, 100), 5));
    // Leading zero octets are a valid Unsigned.
    assert_eq!(
        decode_prescale(&[0x0A, 0x00, 0x05, 0x19, 0x64], 0).unwrap(),
        (prescale(5, 100), 5)
    );
}

#[test]
fn scale_and_prescale_reject_other_tags_and_malformed_contents() {
    let scales: &[(&str, &[u8])] = &[
        ("application REAL", &[0x44, 0x3F, 0x80, 0x00, 0x00]),
        ("application INTEGER", &[0x31, 0x02]),
        ("context tag 2", &[0x29, 0x01]),
        ("framed float", &[0x0E, 0x44, 0x3F, 0x80, 0x00, 0x00, 0x0F]),
        ("three-octet float", &[0x0B, 0x3F, 0x80, 0x00]),
        ("empty integer", &[0x18]),
        ("five-octet integer", &[0x1D, 0x05, 0x01, 0, 0, 0, 0]),
    ];
    for (name, bytes) in scales {
        assert!(
            matches!(decode_scale(bytes, 0), Err(Error::Decoding { .. })),
            "{name}: {:?}",
            decode_scale(bytes, 0)
        );
    }
    let prescales: &[(&str, &[u8])] = &[
        ("application Unsigneds", &[0x21, 0x05, 0x21, 0x64]),
        ("modulo divide missing", &[0x09, 0x05]),
        ("members swapped", &[0x19, 0x64, 0x09, 0x05]),
        ("empty multiplier", &[0x08, 0x19, 0x64]),
    ];
    for (name, bytes) in prescales {
        assert!(decode_prescale(bytes, 0).is_err(), "{name}");
    }
    // Past unsigned32, the width the object keeps.
    assert!(decode_prescale(&[0x0D, 0x05, 0x01, 0, 0, 0, 0, 0x19, 0x01], 0).is_err());
    assert!(matches!(
        decode_scale(&[0x0C, 0x3F, 0x80], 0),
        Err(Error::BufferTooShort { .. })
    ));
}

#[test]
fn members_cut_short_are_a_short_buffer() {
    for (_, wire) in scale_vectors() {
        super::assert_members_cut_short("BACnetScale", &wire, |data| decode_scale(data, 0));
    }
    for (_, wire) in prescale_vectors() {
        super::assert_members_cut_short("BACnetPrescale", &wire, |data| decode_prescale(data, 0));
    }
}
