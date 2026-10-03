use super::*;
use bacnet_encoding::npdu::decode_npdu;
use bacnet_transport::port::TransportProvenance;
use bytes::Bytes;

fn parse(bytes: &[u8], group: bool) -> Option<NumberControl> {
    NumberControl::parse(&ReceivedNetworkControl {
        npdu: decode_npdu(Bytes::copy_from_slice(bytes)).unwrap(),
        source_mac: [2].as_slice().into(),
        link_layer_group: group,
        data_attributes: vec![],
        provenance: TransportProvenance::unverified(),
        ingress_sequence: 19,
    })
}
#[test]
fn number_control_independent_wire_vectors_and_reply_flags() {
    for group in [false, true] {
        assert_eq!(parse(&[1, 0x80, 0x12], group), Some(NumberControl::WhatIs));
    }
    assert_eq!(
        parse(&[1, 0x80, 0x13, 0, 77, 1], true),
        Some(NumberControl::NumberIs {
            number: 77,
            flag: 1
        })
    );
    for bytes in [
        vec![1, 0x80, 0x12, 0],
        vec![1, 0x80, 0x13, 0, 77],
        vec![1, 0x80, 0x13, 0, 77, 1, 0],
        vec![1, 0x80, 0x13, 0, 0, 1],
        vec![1, 0x80, 0x13, 255, 255, 1],
        vec![1, 0x80, 0x13, 0, 77, 2],
        vec![1, 0x88, 0, 4, 1, 9, 0x12],
        vec![1, 0xa0, 255, 255, 0, 255, 0x12],
        vec![1, 0x88, 0, 4, 1, 9, 0x13, 0, 77, 1],
        vec![1, 0xa0, 255, 255, 0, 255, 0x13, 0, 77, 1],
        vec![1, 0x80, 0x03, 4, 0, 100],
        vec![1, 0, 0x12],
    ] {
        assert_eq!(parse(&bytes, true), None, "{bytes:?}");
    }
    assert_eq!(parse(&[1, 0x80, 0x13, 0, 77, 1], false), None);
    let mut state = NetworkNumber::default();
    assert_eq!(number_is_reply(state), None);
    state.observe(77, 1);
    assert_eq!(number_is_reply(state), Some([1, 0x80, 0x13, 0, 77, 0]));
    assert_eq!(
        number_is_reply(NetworkNumber::configured(77).unwrap()),
        Some([1, 0x80, 0x13, 0, 77, 1])
    );
}

#[test]
fn local_network_number_shares_the_last_published_state() {
    let slot = LocalNetworkNumber::default();
    let reader = slot.clone();
    assert_eq!(reader.get(), None);
    let mut state = NetworkNumber::default();
    slot.publish(state);
    assert_eq!(reader.get(), None);
    state.observe(77, 0);
    slot.publish(state);
    assert_eq!(reader.get(), Some(77));
    state.observe(78, 1);
    slot.publish(state);
    assert_eq!(reader.get(), Some(78));
    slot.publish(NetworkNumber::configured(65534).unwrap());
    assert_eq!(reader.get(), Some(65534));
    // A new state that is unknown again (a fresh owner) reads as unknown.
    slot.publish(NetworkNumber::configured(0).unwrap());
    assert_eq!(reader.get(), None);
}
