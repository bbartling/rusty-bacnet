use crate::data_attributes::DataAttribute;
use crate::sc_connection::{ScConnection, ScConnectionState};
use crate::sc_frame::{
    decode_sc_bvlc_result, ScBvlcResult, ScFunction, ScMessage, ScOption, Vmac, BROADCAST_VMAC,
};
use bacnet_types::enums::{ErrorClass, ErrorCode};
use bytes::Bytes;

fn connected() -> ScConnection {
    let mut conn = ScConnection::new([0x01; 6]);
    conn.state = ScConnectionState::Connected;
    conn.hub_vmac = Some([0x10; 6]);
    conn
}

fn encapsulated_npdu_with_data_option(
    message_id: u16,
    destination_vmac: Option<Vmac>,
    option: ScOption,
) -> ScMessage {
    ScMessage {
        function: ScFunction::EncapsulatedNpdu,
        message_id,
        originating_vmac: Some([0x10; 6]),
        destination_vmac,
        dest_options: Vec::new(),
        data_options: vec![option],
        payload: Bytes::from_static(&[0x01, 0x00, 0x30]),
    }
}

#[test]
fn receive_preserves_data_options_as_attributes() {
    let mut conn = connected();
    let msg = ScMessage {
        function: ScFunction::EncapsulatedNpdu,
        message_id: 42,
        originating_vmac: Some([0x10; 6]),
        destination_vmac: Some([0x01; 6]),
        dest_options: Vec::new(),
        data_options: vec![
            ScOption {
                option_type: 1,
                must_understand: true,
                data: Vec::new(),
            },
            ScOption {
                option_type: 31,
                must_understand: false,
                data: vec![0x12, 0x34, 0x56],
            },
        ],
        payload: Bytes::from_static(&[0x01, 0x04]),
    };

    let received = conn.handle_received(&msg).unwrap();
    assert_eq!(received.npdu.as_ref(), &[0x01, 0x04]);
    assert_eq!(received.source_vmac, [0x10; 6]);
    assert_eq!(received.data_attributes.len(), 2);
    assert_eq!(received.data_attributes[0].option_type, 1);
    assert!(received.data_attributes[0].must_understand);
    assert!(received.data_attributes[0].data.is_empty());
    assert_eq!(received.data_attributes[1].option_type, 31);
    assert!(!received.data_attributes[1].must_understand);
    assert_eq!(received.data_attributes[1].data, vec![0x12, 0x34, 0x56]);
}

#[test]
fn build_encapsulated_npdu_encodes_data_attributes_as_options() {
    let mut conn = connected();
    let attributes = vec![
        DataAttribute {
            option_type: 1,
            must_understand: true,
            data: Vec::new(),
        },
        DataAttribute {
            option_type: 31,
            must_understand: false,
            data: vec![0x12, 0x34, 0x56],
        },
    ];

    let msg = conn
        .build_encapsulated_npdu_with_data_attributes([0x02; 6], &[0x01, 0x02], &attributes)
        .unwrap();
    assert!(msg.originating_vmac.is_none());
    assert_eq!(msg.destination_vmac, Some([0x02; 6]));
    assert_eq!(msg.data_options.len(), 2);
    assert_eq!(msg.data_options[0].option_type, 1);
    assert!(msg.data_options[0].must_understand);
    assert!(msg.data_options[0].data.is_empty());
    assert_eq!(msg.data_options[1].option_type, 31);
    assert!(!msg.data_options[1].must_understand);
    assert_eq!(msg.data_options[1].data, vec![0x12, 0x34, 0x56]);
}

#[test]
fn build_encapsulated_npdu_rejects_invalid_data_attribute_type() {
    let mut conn = connected();
    let invalid = DataAttribute {
        option_type: 0,
        must_understand: false,
        data: Vec::new(),
    };

    assert!(conn
        .build_encapsulated_npdu_with_data_attributes([0x02; 6], &[0x01], &[invalid])
        .is_err());
}

#[test]
fn build_encapsulated_npdu_rejects_too_many_data_attributes() {
    let mut conn = connected();
    let attributes = vec![
        DataAttribute {
            option_type: 1,
            must_understand: false,
            data: Vec::new(),
        };
        65
    ];

    assert!(conn
        .build_encapsulated_npdu_with_data_attributes([0x02; 6], &[0x01], &attributes)
        .is_err());
}

#[test]
fn build_encapsulated_npdu_rejects_oversize_data_attribute_payload() {
    let mut conn = connected();
    let attribute = DataAttribute {
        option_type: 1,
        must_understand: false,
        data: vec![0; u16::MAX as usize + 1],
    };

    let err = conn
        .build_encapsulated_npdu_with_data_attributes([0x02; 6], &[0x01], &[attribute])
        .unwrap_err();
    assert!(err.to_string().contains("exceeds 65535"));
}

#[test]
fn unsupported_must_understand_data_option_unicast_returns_nak() {
    let conn = connected();
    let option = ScOption {
        option_type: 2,
        must_understand: true,
        data: Vec::new(),
    };
    let msg = encapsulated_npdu_with_data_option(0x2233, None, option);

    let nak = conn
        .unsupported_must_understand_result(&msg)
        .expect("unsupported data option should be rejected")
        .expect("unicast should return NAK");
    assert_eq!(nak.message_id, msg.message_id);
    assert!(nak.data_options.is_empty());
    assert_eq!(
        decode_sc_bvlc_result(&nak).unwrap(),
        ScBvlcResult::Nak {
            result_for: ScFunction::EncapsulatedNpdu,
            error_header_marker: 0x42,
            error_class: ErrorClass::COMMUNICATION.to_raw(),
            error_code: ErrorCode::HEADER_NOT_UNDERSTOOD.to_raw(),
            error_details: String::new(),
        }
    );
}

#[test]
fn unsupported_must_understand_data_option_broadcast_drops_without_nak() {
    let conn = connected();
    let option = ScOption {
        option_type: 31,
        must_understand: true,
        data: vec![0x12, 0x34, 0x56],
    };
    let msg = encapsulated_npdu_with_data_option(0x3344, Some(BROADCAST_VMAC), option);

    let result = conn
        .unsupported_must_understand_result(&msg)
        .expect("unsupported broadcast should be dropped");
    assert!(result.is_none());
}

#[test]
fn unsupported_non_must_understand_data_option_is_preserved() {
    let mut conn = connected();
    let option = ScOption {
        option_type: 2,
        must_understand: false,
        data: vec![0xAA],
    };
    let msg = encapsulated_npdu_with_data_option(0x4455, Some([0x01; 6]), option.clone());

    assert!(conn.unsupported_must_understand_result(&msg).is_none());
    let received = conn.handle_received(&msg).unwrap();
    assert_eq!(received.data_attributes.len(), 1);
    assert_eq!(received.data_attributes[0].option_type, option.option_type);
    assert_eq!(
        received.data_attributes[0].must_understand,
        option.must_understand
    );
    assert_eq!(received.data_attributes[0].data, option.data);
}
