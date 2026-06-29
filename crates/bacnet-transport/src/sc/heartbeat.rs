use crate::sc_frame::{ScFunction, ScMessage};

pub(super) fn is_bvlc_result_wire(data: &[u8]) -> bool {
    data.first()
        .is_some_and(|function| *function == ScFunction::Result.to_raw())
}

pub(super) fn ack_matches_outstanding(msg: &ScMessage, expected_message_id: Option<u16>) -> bool {
    msg.function == ScFunction::HeartbeatAck
        && expected_message_id.is_some_and(|message_id| msg.message_id == message_id)
        && msg.originating_vmac.is_none()
        && msg.destination_vmac.is_none()
        && msg.data_options.is_empty()
        && msg.payload.is_empty()
}
