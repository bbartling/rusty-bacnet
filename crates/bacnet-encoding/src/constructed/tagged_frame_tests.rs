//! The walk behind [`misplaced_kind`](super::misplaced_kind): whether a
//! closing tag closes the innermost frame open where it stands (#1446).

use super::closes_open_frame;

#[test]
fn a_closing_tag_closes_the_frame_open_at_its_offset() {
    // [0] { Unsigned 5 } [0]
    let data = [0x0E, 0x21, 0x05, 0x0F];
    assert!(closes_open_frame(&data, 3, 0));
    assert!(!closes_open_frame(&data, 3, 1));
    // Nothing is open at the start, or after the frame closes.
    assert!(!closes_open_frame(&[0x0F], 0, 0));
    assert!(!closes_open_frame(&[0x0E, 0x0F, 0x0F], 2, 0));
}

#[test]
fn an_application_boolean_has_no_contents_to_skip() {
    // [1] { BOOLEAN TRUE } [1]: the header's length field is the value, so
    // the walk must not step over the next octet.
    let data = [0x1E, 0x11, 0x1F];
    assert!(closes_open_frame(&data, 2, 1));
    // A context-tagged BOOLEAN does carry one octet of contents.
    let data = [0x1E, 0x19, 0x01, 0x1F];
    assert!(closes_open_frame(&data, 3, 1));
}

#[test]
fn a_closing_tag_of_an_outer_frame_closes_nothing() {
    // [0] { [1] { Unsigned 5 [0]: the closing [0] matches the outer frame
    // while [1] is still open.
    let data = [0x0E, 0x1E, 0x21, 0x05, 0x0F];
    assert!(!closes_open_frame(&data, 4, 0));
    assert!(closes_open_frame(&data, 4, 1));
    // A mismatched closing tag before `at` stops the walk.
    let data = [0x0E, 0x1F, 0x0F];
    assert!(!closes_open_frame(&data, 2, 0));
}

#[test]
fn a_walk_that_steps_past_the_offset_says_no() {
    // [0] { OCTET STRING 0F 0F } [0]: offset 2 is inside the string's
    // contents, which only look like a closing tag.
    let data = [0x0E, 0x62, 0x0F, 0x0F, 0x0F];
    assert!(!closes_open_frame(&data, 2, 0));
    assert!(!closes_open_frame(&data, 3, 0));
    assert!(closes_open_frame(&data, 4, 0));
    // So does a header cut short before the offset: an extended length
    // with no length octet.
    assert!(!closes_open_frame(&[0x0E, 0x25], 2, 0));
}
