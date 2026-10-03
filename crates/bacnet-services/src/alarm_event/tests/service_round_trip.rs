use super::*;
use bacnet_types::enums::EventState;

fn raw_context_unsigned(buf: &mut BytesMut, tag_number: u8, value: &[u8]) {
    bacnet_encoding::tags::encode_tag(
        buf,
        tag_number,
        bacnet_encoding::tags::TagClass::Context,
        value.len() as u32,
    );
    buf.extend_from_slice(value);
}

fn raw_acknowledge_alarm(process_id: &[u8], event_state: &[u8], field_tags: [u8; 6]) -> BytesMut {
    let mut buf = BytesMut::new();
    raw_context_unsigned(&mut buf, field_tags[0], process_id);
    let oid = ObjectIdentifier::new(ObjectType::ANALOG_INPUT, 1).unwrap();
    primitives::encode_ctx_object_id(&mut buf, field_tags[1], &oid);
    raw_context_unsigned(&mut buf, field_tags[2], event_state);
    primitives::encode_timestamp(
        &mut buf,
        field_tags[3],
        &BACnetTimeStamp::SequenceNumber(42),
    )
    .unwrap();
    primitives::encode_ctx_character_string(&mut buf, field_tags[4], "operator").unwrap();
    primitives::encode_timestamp(&mut buf, field_tags[5], &BACnetTimeStamp::SequenceNumber(0))
        .unwrap();
    buf
}

fn raw_acknowledge_alarm_with_source(source: &[u8]) -> BytesMut {
    let mut buf = BytesMut::new();
    raw_context_unsigned(&mut buf, 0, &[1]);
    let oid = ObjectIdentifier::new(ObjectType::ANALOG_INPUT, 1).unwrap();
    primitives::encode_ctx_object_id(&mut buf, 1, &oid);
    raw_context_unsigned(&mut buf, 2, &[EventState::HIGH_LIMIT.to_raw() as u8]);
    primitives::encode_timestamp(&mut buf, 3, &BACnetTimeStamp::SequenceNumber(42)).unwrap();
    bacnet_encoding::tags::encode_tag(
        &mut buf,
        4,
        bacnet_encoding::tags::TagClass::Context,
        source.len() as u32,
    );
    buf.extend_from_slice(source);
    primitives::encode_timestamp(&mut buf, 5, &BACnetTimeStamp::SequenceNumber(7)).unwrap();
    buf
}

#[test]
fn acknowledge_alarm_round_trip() {
    let req = AcknowledgeAlarmRequest {
        acknowledging_process_identifier: 1,
        event_object_identifier: ObjectIdentifier::new(ObjectType::ANALOG_INPUT, 1).unwrap(),
        event_state_acknowledged: EventState::HIGH_LIMIT,
        timestamp: BACnetTimeStamp::SequenceNumber(42),
        acknowledgment_source: "operator".into(),
        time_of_acknowledgment: BACnetTimeStamp::SequenceNumber(0),
    };
    let mut buf = BytesMut::new();
    req.encode(&mut buf).unwrap();
    let decoded = AcknowledgeAlarmRequest::decode(&buf).unwrap();
    assert_eq!(decoded.acknowledging_process_identifier, 1);
    assert_eq!(decoded.event_object_identifier, req.event_object_identifier);
    assert_eq!(decoded.event_state_acknowledged, EventState::HIGH_LIMIT);
    assert_eq!(decoded.timestamp, BACnetTimeStamp::SequenceNumber(42));
    assert_eq!(decoded.acknowledgment_source, "operator");
}

#[test]
fn acknowledge_alarm_values_must_fit_u32() {
    let max_with_leading_zero = [0, 0xff, 0xff, 0xff, 0xff];
    let decoded = AcknowledgeAlarmRequest::decode(&raw_acknowledge_alarm(
        &max_with_leading_zero,
        &max_with_leading_zero,
        [0, 1, 2, 3, 4, 5],
    ))
    .unwrap();
    assert_eq!(decoded.acknowledging_process_identifier, u32::MAX);
    assert_eq!(
        decoded.event_state_acknowledged,
        EventState::from_raw(u32::MAX)
    );

    let too_wide = [1, 0, 0, 0, 0];
    assert!(AcknowledgeAlarmRequest::decode(&raw_acknowledge_alarm(
        &too_wide,
        &[0],
        [0, 1, 2, 3, 4, 5],
    ))
    .is_err());
    assert!(AcknowledgeAlarmRequest::decode(&raw_acknowledge_alarm(
        &[0],
        &too_wide,
        [0, 1, 2, 3, 4, 5],
    ))
    .is_err());
}

#[test]
fn acknowledge_alarm_requires_owned_context_tags() {
    for field in 0..6 {
        let mut field_tags = [0, 1, 2, 3, 4, 5];
        field_tags[field] = 6;
        assert!(
            AcknowledgeAlarmRequest::decode(&raw_acknowledge_alarm(&[1], &[1], field_tags))
                .is_err()
        );
    }

    let mut application_tagged = raw_acknowledge_alarm(&[1], &[1], [0, 1, 2, 3, 4, 5]);
    application_tagged[0] &= !0x08;
    assert!(AcknowledgeAlarmRequest::decode(&application_tagged).is_err());
}

#[test]
fn acknowledge_alarm_rejects_trailing_data() {
    let mut encoded = raw_acknowledge_alarm(&[1], &[1], [0, 1, 2, 3, 4, 5]);
    primitives::encode_ctx_unsigned(&mut encoded, 6, 1);
    assert!(AcknowledgeAlarmRequest::decode(&encoded).is_err());
}

#[test]
fn acknowledge_alarm_sanitizes_unsupported_or_invalid_source_text() {
    for source in [
        &[1, 0xff][..],
        &[2, 0xff][..],
        &[3, 0xff][..],
        &[0xff, 0xff][..],
        &[0, 0xff][..],
        &[4, 0xd8, 0x00][..],
        &[4, 0x00][..],
    ] {
        let decoded =
            AcknowledgeAlarmRequest::decode(&raw_acknowledge_alarm_with_source(source)).unwrap();
        assert_eq!(decoded.acknowledgment_source, "", "source {source:?}");
        assert_eq!(decoded.timestamp, BACnetTimeStamp::SequenceNumber(42));
        assert_eq!(
            decoded.time_of_acknowledgment,
            BACnetTimeStamp::SequenceNumber(7)
        );
    }
}

#[test]
fn acknowledge_alarm_rejects_source_without_charset_framing() {
    assert!(AcknowledgeAlarmRequest::decode(&raw_acknowledge_alarm_with_source(&[])).is_err());
}

#[test]
fn get_event_info_empty_request() {
    let req = GetEventInformationRequest {
        last_received_object_identifier: None,
    };
    let mut buf = BytesMut::new();
    req.encode(&mut buf);
    let decoded = GetEventInformationRequest::decode(&buf).unwrap();
    assert!(decoded.last_received_object_identifier.is_none());
}

#[test]
fn get_event_info_with_last_received() {
    let oid = ObjectIdentifier::new(ObjectType::ANALOG_INPUT, 5).unwrap();
    let req = GetEventInformationRequest {
        last_received_object_identifier: Some(oid),
    };
    let mut buf = BytesMut::new();
    req.encode(&mut buf);
    let decoded = GetEventInformationRequest::decode(&buf).unwrap();
    assert_eq!(decoded.last_received_object_identifier, Some(oid));
}

// -----------------------------------------------------------------------
// Malformed-input decode error tests
// -----------------------------------------------------------------------

#[test]
fn test_decode_acknowledge_alarm_empty_input() {
    assert!(AcknowledgeAlarmRequest::decode(&[]).is_err());
}

#[test]
fn test_decode_acknowledge_alarm_truncated_1_byte() {
    let req = AcknowledgeAlarmRequest {
        acknowledging_process_identifier: 1,
        event_object_identifier: ObjectIdentifier::new(ObjectType::ANALOG_INPUT, 1).unwrap(),
        event_state_acknowledged: EventState::HIGH_LIMIT,
        timestamp: BACnetTimeStamp::SequenceNumber(42),
        acknowledgment_source: "operator".into(),
        time_of_acknowledgment: BACnetTimeStamp::SequenceNumber(0),
    };
    let mut buf = BytesMut::new();
    req.encode(&mut buf).unwrap();
    assert!(AcknowledgeAlarmRequest::decode(&buf[..1]).is_err());
}

#[test]
fn test_decode_acknowledge_alarm_truncated_3_bytes() {
    let req = AcknowledgeAlarmRequest {
        acknowledging_process_identifier: 1,
        event_object_identifier: ObjectIdentifier::new(ObjectType::ANALOG_INPUT, 1).unwrap(),
        event_state_acknowledged: EventState::HIGH_LIMIT,
        timestamp: BACnetTimeStamp::SequenceNumber(42),
        acknowledgment_source: "operator".into(),
        time_of_acknowledgment: BACnetTimeStamp::SequenceNumber(0),
    };
    let mut buf = BytesMut::new();
    req.encode(&mut buf).unwrap();
    assert!(AcknowledgeAlarmRequest::decode(&buf[..3]).is_err());
}

#[test]
fn test_decode_acknowledge_alarm_truncated_half() {
    let req = AcknowledgeAlarmRequest {
        acknowledging_process_identifier: 1,
        event_object_identifier: ObjectIdentifier::new(ObjectType::ANALOG_INPUT, 1).unwrap(),
        event_state_acknowledged: EventState::HIGH_LIMIT,
        timestamp: BACnetTimeStamp::SequenceNumber(42),
        acknowledgment_source: "operator".into(),
        time_of_acknowledgment: BACnetTimeStamp::SequenceNumber(0),
    };
    let mut buf = BytesMut::new();
    req.encode(&mut buf).unwrap();
    let half = buf.len() / 2;
    assert!(AcknowledgeAlarmRequest::decode(&buf[..half]).is_err());
}

#[test]
fn test_decode_acknowledge_alarm_invalid_tag() {
    assert!(AcknowledgeAlarmRequest::decode(&[0xFF, 0xFF, 0xFF]).is_err());
}

#[test]
fn test_decode_get_event_info_invalid_tag() {
    assert!(GetEventInformationRequest::decode(&[0x19, 0]).is_err());
}

#[test]
fn test_decode_get_event_info_truncated() {
    let oid = ObjectIdentifier::new(ObjectType::ANALOG_INPUT, 5).unwrap();
    let req = GetEventInformationRequest {
        last_received_object_identifier: Some(oid),
    };
    let mut buf = BytesMut::new();
    req.encode(&mut buf);
    assert!(GetEventInformationRequest::decode(&buf[..1]).is_err());
}
