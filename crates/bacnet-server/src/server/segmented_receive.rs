use super::*;

/// Apply the Clause 5.4.5.2 duplicate or out-of-order receive transition.
pub(super) fn classify_non_next_segment(
    state: &mut SegmentedRequestState,
    invoke_id: u8,
    sequence_number: u8,
) -> Option<SegmentAckPdu> {
    let is_duplicate = duplicate_in_window(
        sequence_number,
        state.initial_sequence_number,
        state.last_acked_seq,
    );
    if is_duplicate && state.duplicate_count < state.actual_window_size {
        state.duplicate_count += 1;
        debug!(
            invoke_id,
            seq = sequence_number,
            duplicate_count = state.duplicate_count,
            "Silently discarding duplicate segment"
        );
        return None;
    }

    if is_duplicate {
        warn!(
            invoke_id,
            seq = sequence_number,
            "Duplicate allowance exhausted, sending negative SegmentAck"
        );
    } else {
        warn!(
            invoke_id,
            expected = state.expected_seq,
            received = sequence_number,
            "Segment gap detected, sending negative SegmentAck"
        );
    }
    state.initial_sequence_number = state.last_acked_seq;
    state.duplicate_count = 0;
    Some(SegmentAckPdu {
        negative_ack: true,
        sent_by_server: true,
        invoke_id,
        sequence_number: state.last_acked_seq,
        actual_window_size: state.actual_window_size,
    })
}
