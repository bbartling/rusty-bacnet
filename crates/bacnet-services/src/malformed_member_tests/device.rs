//! Remote device management: DeviceCommunicationControl,
//! ReinitializeDevice, TimeSynchronization, the PrivateTransfer request and
//! acknowledgment, and TextMessage. TimeSynchronization is application-tagged
//! (Clause 21); the others read context tags. DeviceCommunicationControl,
//! ReinitializeDevice and PrivateTransfer leave octets after their members
//! unread.

use super::*;
use crate::device_mgmt::{
    DeviceCommunicationControlRequest, ReinitializeDeviceRequest, TimeSynchronizationRequest,
};
use crate::private_transfer::{PrivateTransferAck, PrivateTransferRequest};
use crate::text_message::TextMessageRequest;

#[test]
fn device_communication_control_request() {
    // Five minutes, ENABLE, password "A".
    let rows: &[Row<'_>] = &[
        (
            "well formed",
            &[0x09, 0x05, 0x19, 0x00, 0x2A, 0x00, 0x41],
            Decodes,
        ),
        ("only enable-disable", &[0x19, 0x00], Decodes),
        ("duration cut short", &[0x0A, 0x05], Short),
        (
            "enable-disable as an application tag",
            &[0x09, 0x05, 0x91, 0x00],
            Malformed,
        ),
        ("enable-disable cut short", &[0x09, 0x05, 0x1A, 0x00], Short),
        ("enable-disable missing", &[0x09, 0x05], Malformed),
        ("password cut short", &[0x19, 0x00, 0x2B, 0x00, 0x41], Short),
        (
            "password as an application tag",
            &[0x19, 0x00, 0x72, 0x00, 0x41],
            Decodes,
        ),
        (
            "an octet after the password",
            &[0x19, 0x00, 0x2A, 0x00, 0x41, 0x00],
            Decodes,
        ),
    ];
    check(decoder!(DeviceCommunicationControlRequest), rows);
}

#[test]
fn reinitialize_device_request() {
    // COLDSTART, password "A".
    let rows: &[Row<'_>] = &[
        ("well formed", &[0x09, 0x00, 0x1A, 0x00, 0x41], Decodes),
        ("state as an application tag", &[0x91, 0x00], Malformed),
        ("state cut short", &[0x0A, 0x00], Short),
        ("password cut short", &[0x09, 0x00, 0x1B, 0x00, 0x41], Short),
        ("an octet after the state", &[0x09, 0x00, 0x00], Decodes),
    ];
    check(decoder!(ReinitializeDeviceRequest), rows);
}

#[test]
fn time_synchronization_request() {
    let date: &[u8] = &[0xA4, 0x7E, 0x0A, 0x03, 0x06];
    let time: &[u8] = &[0xB4, 0x0C, 0x1E, 0x00, 0x00];
    let rows: &[Row<'_>] = &[
        ("well formed", &cat(&[date, time]), Decodes),
        (
            "date as context [10]",
            &cat(&[&[0xAC, 0x7E, 0x0A, 0x03, 0x06], time]),
            Malformed,
        ),
        (
            "date of three octets",
            &cat(&[&[0xA3, 0x7E, 0x0A, 0x03], time]),
            Malformed,
        ),
        ("date cut short", &[0xA4, 0x7E, 0x0A], Short),
        (
            "time as a Date",
            &cat(&[date, &[0xA4, 0x0C, 0x1E, 0x00, 0x00]]),
            Malformed,
        ),
        ("time cut short", &cat(&[date, &[0xB4, 0x0C, 0x1E]]), Short),
        (
            "an octet after the time",
            &cat(&[date, time, &[0x00]]),
            Malformed,
        ),
    ];
    check(decoder!(TimeSynchronizationRequest), rows);
}

/// Vendor 7, service 1 and an Unsigned 5 as the block: the request's and the
/// acknowledgment's shared rows.
fn private_transfer_rows() -> Vec<(&'static str, Vec<u8>, Kind)> {
    vec![
        (
            "well formed",
            vec![0x09, 0x07, 0x19, 0x01, 0x2E, 0x21, 0x05, 0x2F],
            Decodes,
        ),
        ("without the block", vec![0x09, 0x07, 0x19, 0x01], Decodes),
        (
            "vendor as an application tag",
            vec![0x21, 0x07, 0x19, 0x01],
            Malformed,
        ),
        ("vendor cut short", vec![0x0A, 0x07], Short),
        (
            "service number as [2]",
            vec![0x09, 0x07, 0x29, 0x01],
            Malformed,
        ),
        (
            "service number cut short",
            vec![0x09, 0x07, 0x1A, 0x01],
            Short,
        ),
        (
            "block not closed",
            vec![0x09, 0x07, 0x19, 0x01, 0x2E, 0x21, 0x05],
            Malformed,
        ),
        (
            "an octet after the service number",
            vec![0x09, 0x07, 0x19, 0x01, 0x00],
            Decodes,
        ),
    ]
}

#[test]
fn private_transfer_request_and_ack() {
    let owned = private_transfer_rows();
    let rows: Vec<Row<'_>> = owned
        .iter()
        .map(|(row, input, kind)| (*row, input.as_slice(), *kind))
        .collect();
    check(decoder!(PrivateTransferRequest), &rows);
    check(decoder!(PrivateTransferAck), &rows);
}

#[test]
fn text_message_request() {
    let source: &[u8] = &[0x0C, 0x02, 0x00, 0x00, 0x01];
    // Numeric class 3, NORMAL, message "H".
    let class: &[u8] = &[0x1E, 0x09, 0x03, 0x1F];
    let priority: &[u8] = &[0x29, 0x00];
    let message: &[u8] = &[0x3A, 0x00, 0x48];
    let rows: &[Row<'_>] = &[
        (
            "well formed",
            &cat(&[source, class, priority, message]),
            Decodes,
        ),
        (
            "without a class",
            &cat(&[source, priority, message]),
            Decodes,
        ),
        (
            "text class",
            &cat(&[source, &[0x1E, 0x1A, 0x00, 0x43, 0x1F], priority, message]),
            Decodes,
        ),
        (
            "source as an application tag",
            &cat(&[&[0xC4, 0x02, 0x00, 0x00, 0x01], priority, message]),
            Malformed,
        ),
        ("source cut short", &[0x0C, 0x02, 0x00], Short),
        (
            "class as [2]",
            &cat(&[source, &[0x1E, 0x29, 0x03, 0x1F], priority, message]),
            Malformed,
        ),
        (
            "class cut short inside its frame",
            &cat(&[source, &[0x1E, 0x0A, 0x03, 0x1F]]),
            Malformed,
        ),
        ("priority cut short", &cat(&[source, &[0x2A, 0x00]]), Short),
        (
            "message as an application tag",
            &cat(&[source, priority, &[0x72, 0x00, 0x48]]),
            Malformed,
        ),
        (
            "message cut short",
            &cat(&[source, priority, &[0x3B, 0x00, 0x48]]),
            Short,
        ),
        (
            "an octet after the message",
            &cat(&[source, priority, message, &[0x00]]),
            Malformed,
        ),
    ];
    check(decoder!(TextMessageRequest), rows);
}
