//! The alarm and enrollment summaries and the VT-Data acknowledgment. The
//! summary ACKs are application-tagged (Clause 21); GetEnrollmentSummary's
//! request and VTDataAck read context tags.

use super::*;
use crate::alarm_summary::GetAlarmSummaryAck;
use crate::enrollment_summary::{GetEnrollmentSummaryAck, GetEnrollmentSummaryRequest};
use crate::virtual_terminal::VTDataAck;

/// AI-1 as an application object identifier.
const AI_1: &[u8] = &[0xC4, 0x00, 0x00, 0x00, 0x01];

#[test]
fn get_alarm_summary_ack() {
    // HIGH_LIMIT, then TO-OFFNORMAL and TO-NORMAL acknowledged.
    let state: &[u8] = &[0x91, 0x03];
    let acked: &[u8] = &[0x82, 0x05, 0xA0];
    let rows: &[Row<'_>] = &[
        ("no entries", &[], Decodes),
        ("one entry", &cat(&[AI_1, state, acked]), Decodes),
        (
            "identifier as context [0]",
            &cat(&[&[0x0C, 0x00, 0x00, 0x00, 0x01], state, acked]),
            Malformed,
        ),
        ("identifier cut short", &[0xC4, 0x00, 0x00], Short),
        (
            "state as an Unsigned",
            &cat(&[AI_1, &[0x21, 0x03], acked]),
            Malformed,
        ),
        ("state cut short", &cat(&[AI_1, &[0x92, 0x03]]), Short),
        (
            "transitions as context [0]",
            &cat(&[AI_1, state, &[0x0A, 0x05, 0xA0]]),
            Malformed,
        ),
        (
            "transitions cut short",
            &cat(&[AI_1, state, &[0x82, 0x05]]),
            Short,
        ),
        (
            "an octet after the entry",
            &cat(&[AI_1, state, acked, &[0x00]]),
            Malformed,
        ),
    ];
    check(decoder!(GetAlarmSummaryAck), rows);
}

#[test]
fn get_enrollment_summary_request() {
    let all: &[u8] = &[0x09, 0x00];
    // Device 1, process 5.
    let enrollment: &[u8] = &[
        0x1E, 0x0E, 0x0C, 0x02, 0x00, 0x00, 0x01, 0x0F, 0x19, 0x05, 0x1F,
    ];
    let rows: &[Row<'_>] = &[
        ("only the acknowledgment filter", all, Decodes),
        (
            "every filter",
            &cat(&[
                all,
                enrollment,
                &[
                    0x29, 0x01, 0x39, 0x00, 0x4E, 0x09, 0x01, 0x19, 0x05, 0x4F, 0x59, 0x0A,
                ],
            ]),
            Decodes,
        ),
        (
            "acknowledgment filter as an application tag",
            &[0x91, 0x00],
            Malformed,
        ),
        ("acknowledgment filter cut short", &[0x0A, 0x00], Short),
        (
            "acknowledgment filter 3",
            &[0x09, 0x03],
            Kind::Reject(RejectReason::UNDEFINED_ENUMERATION),
        ),
        (
            "process identifier as an application tag",
            &cat(&[
                all,
                &[
                    0x1E, 0x0E, 0x0C, 0x02, 0x00, 0x00, 0x01, 0x0F, 0x21, 0x05, 0x1F,
                ],
            ]),
            Malformed,
        ),
        (
            "event state filter cut short",
            &cat(&[all, &[0x2A, 0x01]]),
            Short,
        ),
        (
            "event type filter cut short",
            &cat(&[all, &[0x3A, 0x00]]),
            Short,
        ),
        (
            "priority filter cut short inside its frame",
            &cat(&[all, &[0x4E, 0x0A, 0x01, 0x4F]]),
            Malformed,
        ),
        (
            "priority filter minimum above maximum",
            &cat(&[all, &[0x4E, 0x09, 0x05, 0x19, 0x01, 0x4F]]),
            Kind::Reject(RejectReason::INVALID_DATA_ENCODING),
        ),
        (
            "notification class filter cut short",
            &cat(&[all, &[0x5A, 0x0A]]),
            Short,
        ),
        (
            "an octet after the filters",
            &cat(&[all, &[0x00]]),
            Malformed,
        ),
    ];
    check(decoder!(GetEnrollmentSummaryRequest), rows);
}

#[test]
fn get_enrollment_summary_ack() {
    // OUT_OF_RANGE, HIGH_LIMIT, priority 7.
    let entry: &[u8] = &[0x91, 0x05, 0x91, 0x03, 0x21, 0x07];
    let rows: &[Row<'_>] = &[
        ("one entry", &cat(&[AI_1, entry]), Decodes),
        (
            "with notification class 256",
            &cat(&[AI_1, entry, &[0x22, 0x01, 0x00]]),
            Decodes,
        ),
        (
            "identifier as context [0]",
            &cat(&[&[0x0C, 0x00, 0x00, 0x00, 0x01], entry]),
            Malformed,
        ),
        ("identifier cut short", &[0xC4, 0x00, 0x00], Short),
        (
            "event type as an Unsigned",
            &cat(&[AI_1, &[0x21, 0x05, 0x91, 0x03, 0x21, 0x07]]),
            Malformed,
        ),
        (
            "priority as an ENUMERATED",
            &cat(&[AI_1, &[0x91, 0x05, 0x91, 0x03, 0x91, 0x07]]),
            Malformed,
        ),
        (
            "priority cut short",
            &cat(&[AI_1, &[0x91, 0x05, 0x91, 0x03, 0x22, 0x07]]),
            Short,
        ),
        (
            "notification class cut short",
            &cat(&[AI_1, entry, &[0x22, 0x01]]),
            Short,
        ),
        (
            "an octet after the entry",
            &cat(&[AI_1, entry, &[0x00]]),
            Malformed,
        ),
    ];
    check(decoder!(GetEnrollmentSummaryAck), rows);
}

#[test]
fn vt_data_ack() {
    let rows: &[Row<'_>] = &[
        ("all accepted", &[0x09, 0x01], Decodes),
        ("five accepted", &[0x09, 0x00, 0x19, 0x05], Decodes),
        ("flag as an application BOOLEAN", &[0x11], Malformed),
        ("flag cut short", &[0x09], Short),
        ("flag of two octets, cut short", &[0x0A, 0x00], Malformed),
        ("count cut short", &[0x09, 0x00, 0x1A, 0x05], Short),
        (
            "count as an application tag",
            &[0x09, 0x00, 0x21, 0x05],
            Malformed,
        ),
        ("an octet after the flag", &[0x09, 0x01, 0x00], Malformed),
    ];
    check(decoder!(VTDataAck), rows);
}
