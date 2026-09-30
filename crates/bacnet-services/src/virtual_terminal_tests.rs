use super::*;

fn encoded<F: FnOnce(&mut BytesMut)>(f: F) -> Vec<u8> {
    let mut buf = BytesMut::new();
    f(&mut buf);
    buf.to_vec()
}

fn open(vt_class: VTClass, id: u8) -> VTOpenRequest {
    VTOpenRequest {
        vt_class,
        local_vt_session_identifier: id,
    }
}

fn data(session: u8, octets: &[u8], flag: bool) -> VTDataRequest {
    VTDataRequest {
        vt_session_identifier: session,
        vt_new_data: octets.to_vec(),
        vt_data_flag: flag,
    }
}

// ---------------------------------------------------------------------------
// VT-Open
// ---------------------------------------------------------------------------

#[test]
fn vt_open_default_terminal_bytes() {
    // ENUMERATED 0 is 91 00; Unsigned 5 is 21 05 (Clause 21.2.5, 20.2.4, 20.2.11).
    let req = open(VTClass::DEFAULT_TERMINAL, 5);
    assert_eq!(encoded(|b| req.encode(b)), vec![0x91, 0x00, 0x21, 0x05]);
    assert_eq!(
        VTOpenRequest::decode(&[0x91, 0x00, 0x21, 0x05]).unwrap(),
        req
    );
}

#[test]
fn vt_open_other_class_and_max_identifier_bytes() {
    let req = open(VTClass::DEC_VT100, 255);
    assert_eq!(encoded(|b| req.encode(b)), vec![0x91, 0x03, 0x21, 0xFF]);
    assert_eq!(
        VTOpenRequest::decode(&[0x91, 0x03, 0x21, 0xFF]).unwrap(),
        req
    );
}

#[test]
fn vt_open_round_trip() {
    for class in [0, 1, 6, 64, 65535] {
        let req = open(VTClass::from_raw(class), 42);
        let bytes = encoded(|b| req.encode(b));
        assert_eq!(VTOpenRequest::decode(&bytes).unwrap(), req);
    }
}

#[test]
fn vt_open_requires_local_identifier() {
    assert!(VTOpenRequest::decode(&[0x91, 0x00]).is_err());
}

#[test]
fn vt_open_rejects_trailing_data() {
    assert!(VTOpenRequest::decode(&[0x91, 0x00, 0x21, 0x05, 0x21, 0x06]).is_err());
    assert!(VTOpenRequest::decode(&[0x91, 0x00, 0x21, 0x05, 0x00]).is_err());
}

#[test]
fn vt_open_rejects_wrong_tags_and_order() {
    // Unsigned where ENUMERATED belongs, and swapped fields.
    assert!(VTOpenRequest::decode(&[0x21, 0x00, 0x21, 0x05]).is_err());
    assert!(VTOpenRequest::decode(&[0x21, 0x05, 0x91, 0x00]).is_err());
    // ENUMERATED where the identifier belongs.
    assert!(VTOpenRequest::decode(&[0x91, 0x00, 0x91, 0x05]).is_err());
    // Context-tagged forms are not the production.
    assert!(VTOpenRequest::decode(&[0x09, 0x00, 0x19, 0x05]).is_err());
}

#[test]
fn vt_open_values_must_fit_field_widths() {
    let req = open(VTClass::from_raw(u32::MAX), 0);
    let bytes = encoded(|b| req.encode(b));
    assert_eq!(VTOpenRequest::decode(&bytes).unwrap(), req);

    // Leading zero octets do not count against the width.
    let leading_zero = [0x95, 0x05, 0x00, 0xFF, 0xFF, 0xFF, 0xFF, 0x21, 0x00];
    assert_eq!(
        VTOpenRequest::decode(&leading_zero).unwrap().vt_class,
        VTClass::from_raw(u32::MAX)
    );
    let leading_zero_id = [0x91, 0x00, 0x22, 0x00, 0xFF];
    assert_eq!(
        VTOpenRequest::decode(&leading_zero_id)
            .unwrap()
            .local_vt_session_identifier,
        u8::MAX
    );

    // Class above u32.
    assert!(
        VTOpenRequest::decode(&[0x95, 0x05, 0x01, 0x00, 0x00, 0x00, 0x00, 0x21, 0x00]).is_err()
    );
    // Identifier above u8.
    assert!(VTOpenRequest::decode(&[0x91, 0x00, 0x22, 0x01, 0x00]).is_err());
}

#[test]
fn vt_open_rejects_reserved_lvt_and_truncation() {
    assert!(VTOpenRequest::decode(&[0x96, 0x01, 0x00, 0x21, 0x00]).is_err());
    assert!(VTOpenRequest::decode(&[0x91, 0x00, 0x26, 0x01, 0x00]).is_err());
    assert!(VTOpenRequest::decode(&[0x92, 0x00]).is_err());
    assert!(VTOpenRequest::decode(&[0x91, 0x00, 0x22, 0x01]).is_err());
}

#[test]
fn vt_open_empty_input() {
    assert!(VTOpenRequest::decode(&[]).is_err());
}

// ---------------------------------------------------------------------------
// VT-Open-ACK
// ---------------------------------------------------------------------------

#[test]
fn vt_open_ack_bytes() {
    let ack = VTOpenAck {
        remote_vt_session_identifier: 42,
    };
    assert_eq!(encoded(|b| ack.encode(b)), vec![0x21, 0x2A]);
    assert_eq!(VTOpenAck::decode(&[0x21, 0x2A]).unwrap(), ack);
}

#[test]
fn vt_open_ack_identifier_must_fit_u8() {
    assert_eq!(
        VTOpenAck::decode(&[0x21, 0xFF])
            .unwrap()
            .remote_vt_session_identifier,
        u8::MAX
    );
    assert_eq!(
        VTOpenAck::decode(&[0x22, 0x00, 0xFF])
            .unwrap()
            .remote_vt_session_identifier,
        u8::MAX
    );
    assert!(VTOpenAck::decode(&[0x22, 0x01, 0x00]).is_err());
    assert!(
        VTOpenAck::decode(&[0x25, 0x08, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF]).is_err()
    );
}

#[test]
fn vt_open_ack_rejects_bad_forms() {
    // Wrong tag number, reserved LVT, trailing data, empty input.
    assert!(VTOpenAck::decode(&[0x91, 0x01]).is_err());
    assert!(VTOpenAck::decode(&[0x26, 0x01, 0x00]).is_err());
    assert!(VTOpenAck::decode(&[0x21, 0x01, 0x21, 0x02]).is_err());
    assert!(VTOpenAck::decode(&[]).is_err());
}

// ---------------------------------------------------------------------------
// VT-Close
// ---------------------------------------------------------------------------

#[test]
fn vt_close_bytes() {
    let req = VTCloseRequest {
        list_of_remote_vt_session_identifiers: vec![1, 2, 255],
    };
    let bytes = encoded(|b| req.encode(b).unwrap());
    assert_eq!(bytes, vec![0x21, 0x01, 0x21, 0x02, 0x21, 0xFF]);
    assert_eq!(VTCloseRequest::decode(&bytes).unwrap(), req);
}

#[test]
fn vt_close_empty_list_rejected() {
    let req = VTCloseRequest {
        list_of_remote_vt_session_identifiers: vec![],
    };
    let mut buf = BytesMut::new();
    assert!(req.encode(&mut buf).is_err());
    assert!(buf.is_empty());
    assert!(VTCloseRequest::decode(&[]).is_err());
}

#[test]
fn vt_close_identifiers_must_fit_u8() {
    assert!(VTCloseRequest::decode(&[0x21, 0x01, 0x22, 0x01, 0x00]).is_err());
    assert_eq!(
        VTCloseRequest::decode(&[0x22, 0x00, 0xFF])
            .unwrap()
            .list_of_remote_vt_session_identifiers,
        [u8::MAX]
    );
}

#[test]
fn vt_close_rejects_wrong_tags_and_reserved_lvt() {
    assert!(VTCloseRequest::decode(&[0x91, 0x01]).is_err());
    assert!(VTCloseRequest::decode(&[0x26, 0x01, 0x00]).is_err());
    // A context tag is not a list element.
    assert!(VTCloseRequest::decode(&[0x09, 0x01]).is_err());
    // Truncated second element.
    assert!(VTCloseRequest::decode(&[0x21, 0x01, 0x22, 0x01]).is_err());
}

// ---------------------------------------------------------------------------
// VT-Data
// ---------------------------------------------------------------------------

#[test]
fn vt_data_flag_is_unsigned_bytes() {
    // Flag 1 is 21 01 and flag 0 is 21 00 (Unsigned 0..1), never the Boolean form.
    let req = data(1, &[0x48, 0x69], true);
    let bytes = encoded(|b| req.encode(b));
    assert_eq!(bytes, vec![0x21, 0x01, 0x62, 0x48, 0x69, 0x21, 0x01]);
    assert_eq!(VTDataRequest::decode(&bytes).unwrap(), req);

    let req = data(5, &[0x01], false);
    let bytes = encoded(|b| req.encode(b));
    assert_eq!(bytes, vec![0x21, 0x05, 0x61, 0x01, 0x21, 0x00]);
    assert_eq!(VTDataRequest::decode(&bytes).unwrap(), req);
}

#[test]
fn vt_data_empty_octet_string() {
    let req = data(0, &[], false);
    let bytes = encoded(|b| req.encode(b));
    assert_eq!(bytes, vec![0x21, 0x00, 0x60, 0x21, 0x00]);
    assert_eq!(VTDataRequest::decode(&bytes).unwrap(), req);
}

#[test]
fn vt_data_long_octet_string_round_trip() {
    let payload = vec![0xA5; 300];
    let req = data(9, &payload, true);
    let bytes = encoded(|b| req.encode(b));
    assert_eq!(VTDataRequest::decode(&bytes).unwrap(), req);
}

#[test]
fn vt_data_flag_above_one_rejected() {
    assert!(VTDataRequest::decode(&[0x21, 0x01, 0x61, 0x01, 0x21, 0x02]).is_err());
    assert!(VTDataRequest::decode(&[0x21, 0x01, 0x61, 0x01, 0x22, 0x01, 0x00]).is_err());
    // A leading zero octet is still the value 1.
    assert!(
        VTDataRequest::decode(&[0x21, 0x01, 0x61, 0x01, 0x22, 0x00, 0x01])
            .unwrap()
            .vt_data_flag
    );
}

#[test]
fn vt_data_boolean_flag_rejected() {
    assert!(VTDataRequest::decode(&[0x21, 0x01, 0x61, 0x01, 0x11]).is_err());
    assert!(VTDataRequest::decode(&[0x21, 0x01, 0x61, 0x01, 0x10]).is_err());
}

#[test]
fn vt_data_rejects_trailing_data_and_missing_fields() {
    assert!(VTDataRequest::decode(&[0x21, 0x01, 0x61, 0x01, 0x21, 0x00, 0x21, 0x00]).is_err());
    assert!(VTDataRequest::decode(&[0x21, 0x01, 0x61, 0x01]).is_err());
    assert!(VTDataRequest::decode(&[0x21, 0x01]).is_err());
    assert!(VTDataRequest::decode(&[]).is_err());
}

#[test]
fn vt_data_identifier_must_fit_u8() {
    for bad in [
        &[0x22, 0x01, 0x00, 0x61, 0x01, 0x21, 0x00][..],
        &[0x22, 0x01, 0x01, 0x61, 0x01, 0x21, 0x00][..],
    ] {
        assert!(VTDataRequest::decode(bad).is_err());
    }
    let leading_zero = [0x22, 0x00, 0xFF, 0x61, 0x01, 0x21, 0x00];
    assert_eq!(
        VTDataRequest::decode(&leading_zero)
            .unwrap()
            .vt_session_identifier,
        u8::MAX
    );
}

#[test]
fn vt_data_requires_application_field_tags() {
    // ENUMERATED session id, CharacterString data, Unsigned-tagged octet data.
    assert!(VTDataRequest::decode(&[0x91, 0x01, 0x61, 0x01, 0x21, 0x00]).is_err());
    assert!(VTDataRequest::decode(&[0x21, 0x01, 0x72, 0x00, 0x78, 0x21, 0x00]).is_err());
    assert!(VTDataRequest::decode(&[0x21, 0x01, 0x21, 0x01, 0x21, 0x00]).is_err());
    // Context tags in place of application tags.
    assert!(VTDataRequest::decode(&[0x09, 0x01, 0x61, 0x01, 0x21, 0x00]).is_err());
    assert!(VTDataRequest::decode(&[0x21, 0x01, 0x61, 0x01, 0x09, 0x00]).is_err());
}

#[test]
fn vt_data_rejects_reserved_lvt_forms() {
    assert!(VTDataRequest::decode(&[0x26, 0x01, 0x00, 0x61, 0x01, 0x21, 0x00]).is_err());
    assert!(VTDataRequest::decode(&[0x21, 0x01, 0x66, 0x01, 0x21, 0x00]).is_err());
    assert!(VTDataRequest::decode(&[0x21, 0x01, 0x61, 0x01, 0x26, 0x01, 0x00]).is_err());
}

// ---------------------------------------------------------------------------
// VT-Data-ACK
// ---------------------------------------------------------------------------

#[test]
fn vt_data_ack_all_accepted_bytes() {
    // [0] BOOLEAN TRUE is 09 01; no count.
    let bytes = encoded(|b| VTDataAck::AllAccepted.encode(b));
    assert_eq!(bytes, vec![0x09, 0x01]);
    assert_eq!(VTDataAck::decode(&bytes).unwrap(), VTDataAck::AllAccepted);
}

#[test]
fn vt_data_ack_partial_bytes() {
    // [0] FALSE is 09 00, [1] Unsigned 3 is 19 03.
    let ack = VTDataAck::Partial {
        accepted_octet_count: 3,
    };
    let bytes = encoded(|b| ack.encode(b));
    assert_eq!(bytes, vec![0x09, 0x00, 0x19, 0x03]);
    assert_eq!(VTDataAck::decode(&bytes).unwrap(), ack);
}

#[test]
fn vt_data_ack_zero_and_multi_octet_counts() {
    let zero = VTDataAck::Partial {
        accepted_octet_count: 0,
    };
    let bytes = encoded(|b| zero.encode(b));
    assert_eq!(bytes, vec![0x09, 0x00, 0x19, 0x00]);
    assert_eq!(VTDataAck::decode(&bytes).unwrap(), zero);

    let big = VTDataAck::Partial {
        accepted_octet_count: 300,
    };
    let bytes = encoded(|b| big.encode(b));
    assert_eq!(bytes, vec![0x09, 0x00, 0x1A, 0x01, 0x2C]);
    assert_eq!(VTDataAck::decode(&bytes).unwrap(), big);
}

#[test]
fn vt_data_ack_accessors() {
    assert!(VTDataAck::AllAccepted.all_new_data_accepted());
    assert_eq!(VTDataAck::AllAccepted.accepted_octet_count(), None);
    let partial = VTDataAck::Partial {
        accepted_octet_count: 7,
    };
    assert!(!partial.all_new_data_accepted());
    assert_eq!(partial.accepted_octet_count(), Some(7));
}

#[test]
fn vt_data_ack_requires_accepted_flag() {
    assert!(VTDataAck::decode(&[]).is_err());
    // Only the count, no [0].
    assert!(VTDataAck::decode(&[0x19, 0x03]).is_err());
}

#[test]
fn vt_data_ack_count_pairing_is_enforced_both_ways() {
    // TRUE with a count.
    assert!(VTDataAck::decode(&[0x09, 0x01, 0x19, 0x03]).is_err());
    // FALSE without a count.
    assert!(VTDataAck::decode(&[0x09, 0x00]).is_err());
}

#[test]
fn vt_data_ack_rejects_malformed_flag() {
    // Value other than 0/1, wrong length, application Boolean instead of context.
    assert!(VTDataAck::decode(&[0x09, 0x02]).is_err());
    assert!(VTDataAck::decode(&[0x0A, 0x00, 0x01]).is_err());
    assert!(VTDataAck::decode(&[0x08]).is_err());
    assert!(VTDataAck::decode(&[0x11]).is_err());
}

#[test]
fn vt_data_ack_rejects_trailing_data() {
    assert!(VTDataAck::decode(&[0x09, 0x01, 0x21, 0x00]).is_err());
    assert!(VTDataAck::decode(&[0x09, 0x00, 0x19, 0x03, 0x19, 0x03]).is_err());
    // Fields in the wrong order.
    assert!(VTDataAck::decode(&[0x19, 0x03, 0x09, 0x00]).is_err());
}

#[test]
fn vt_data_ack_count_must_fit_u32() {
    let over = [0x09, 0x00, 0x1D, 0x05, 0x01, 0x00, 0x00, 0x00, 0x00];
    assert!(VTDataAck::decode(&over).is_err());
    let leading_zero = [0x09, 0x00, 0x1D, 0x05, 0x00, 0xFF, 0xFF, 0xFF, 0xFF];
    assert_eq!(
        VTDataAck::decode(&leading_zero).unwrap(),
        VTDataAck::Partial {
            accepted_octet_count: u32::MAX
        }
    );
}
