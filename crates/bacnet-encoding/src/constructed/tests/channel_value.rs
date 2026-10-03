//! BACnetChannelValue extents (Clause 21): one application-tagged primitive,
//! or a lighting command framed in context tag 0.
use super::*;

/// Operation 1 with a target level of 50.0, framed in [0].
const LIGHTING: [u8; 9] = [0x0E, 0x09, 0x01, 0x1C, 0x42, 0x48, 0x00, 0x00, 0x0F];

#[test]
fn primitives_and_a_lighting_command_are_channel_values() {
    let values: [&[u8]; 5] = [
        &[0x00],                         // NULL
        &[0x44, 0x42, 0x90, 0x00, 0x00], // REAL 72.0
        &[0x91, 0x01],                   // ENUMERATED 1
        &[0x73, 0x00, 0x6F, 0x6E],       // CharacterString "on"
        &LIGHTING,
    ];
    for value in values {
        // A value ends where the next one would start.
        let followed = [value, &[0x21, 0x05]].concat();
        assert_eq!(
            channel_value_end(&followed, 0).unwrap(),
            value.len(),
            "{value:02X?}"
        );
        assert_eq!(
            is_lighting_command_channel_value(value),
            value == LIGHTING,
            "{value:02X?}"
        );
    }
    // Fields may be skipped as long as their numbers increase.
    assert!(is_lighting_command_channel_value(&[
        0x0E, 0x09, 0x03, 0x59, 0x10, 0x0F
    ]));
    // Trailing octets make it more than one value.
    assert!(!is_lighting_command_channel_value(
        &[&LIGHTING[..], &[0x00]].concat()
    ));
}

#[test]
fn malformed_lighting_commands_are_refused() {
    let bad: [&[u8]; 8] = [
        // No operation field, and an empty command.
        &[0x0E, 0x1C, 0x42, 0x48, 0x00, 0x00, 0x0F],
        &[0x0E, 0x0F],
        // Fields out of order.
        &[
            0x0E, 0x09, 0x01, 0x2C, 0x40, 0x00, 0x00, 0x00, 0x1C, 0x42, 0x48, 0x00, 0x00, 0x0F,
        ],
        // A REAL field with three octets, and field 6.
        &[0x0E, 0x09, 0x01, 0x1B, 0x42, 0x48, 0x00, 0x0F],
        &[0x0E, 0x09, 0x01, 0x69, 0x00, 0x0F],
        // Priority 0 and 17.
        &[0x0E, 0x09, 0x01, 0x59, 0x00, 0x0F],
        &[0x0E, 0x09, 0x01, 0x59, 0x11, 0x0F],
        // No closing tag.
        &[0x0E, 0x09, 0x01],
    ];
    for value in bad {
        assert!(channel_value_end(value, 0).is_err(), "{value:02X?}");
        assert!(!is_lighting_command_channel_value(value), "{value:02X?}");
    }
    // Any other context tag isn't a channel value at all.
    assert!(channel_value_end(&[0x19, 0x01], 0).is_err());
    assert!(channel_value_end(&[], 0).is_err());
}

#[test]
fn contents_cut_short_are_a_short_buffer() {
    let short = |value: &[u8]| match channel_value_end(value, 0) {
        Err(bacnet_types::error::Error::BufferTooShort { need, have }) => (need, have),
        other => panic!("expected a short buffer for {value:02X?}, got {other:?}"),
    };
    // The operation field says one octet and the data stops.
    assert_eq!(short(&[0x0E, 0x09]), (3, 2));
    // A target level REAL with two of its four octets.
    assert_eq!(short(&[0x0E, 0x09, 0x01, 0x1C, 0x42, 0x48]), (8, 6));
    // An application REAL cut short reads the same way.
    assert_eq!(short(&[0x44, 0x42, 0x90]), (5, 3));
}
