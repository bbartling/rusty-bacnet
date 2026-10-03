//! AtomicReadFile and AtomicWriteFile requests (#1375). The file identifier,
//! start position or record, counts and data are application-tagged (Clause
//! 21's productions for Clauses 14.1 and 14.2), so any other tag is refused.
//! The requests' trailing octets are tolerated, as the server's file handler
//! documents.

use super::*;
use crate::file::{AtomicReadFileRequest, AtomicWriteFileRequest};

/// FILE-1 as an application object identifier.
const FILE_1: &[u8] = &[0xC4, 0x02, 0x80, 0x00, 0x01];

#[test]
fn atomic_read_file_request() {
    // Stream access: start 5, 16 octets.
    let stream = |frame: &[u8]| cat(&[FILE_1, frame]);
    let rows: &[Row<'_>] = &[
        (
            "stream",
            &stream(&[0x0E, 0x31, 0x05, 0x21, 0x10, 0x0F]),
            Decodes,
        ),
        (
            "record",
            &stream(&[0x1E, 0x31, 0x05, 0x21, 0x10, 0x1F]),
            Decodes,
        ),
        (
            "file identifier as context [0]",
            &[
                0x0C, 0x02, 0x80, 0x00, 0x01, 0x0E, 0x31, 0x05, 0x21, 0x10, 0x0F,
            ],
            Malformed,
        ),
        (
            "file identifier as an Unsigned",
            &[
                0x24, 0x02, 0x80, 0x00, 0x01, 0x0E, 0x31, 0x05, 0x21, 0x10, 0x0F,
            ],
            Malformed,
        ),
        ("file identifier cut short", &[0xC4, 0x02, 0x80], Short),
        (
            "file identifier of three octets",
            &[0xC3, 0x02, 0x80, 0x00, 0x0E, 0x31, 0x05, 0x21, 0x10, 0x0F],
            Malformed,
        ),
        (
            "file identifier of five octets, cut short",
            &[0xC5, 0x05, 0x02, 0x80],
            Malformed,
        ),
        (
            "start position as an Unsigned",
            &stream(&[0x0E, 0x21, 0x05, 0x21, 0x10, 0x0F]),
            Malformed,
        ),
        (
            "start position as context [3]",
            &stream(&[0x0E, 0x39, 0x05, 0x21, 0x10, 0x0F]),
            Malformed,
        ),
        (
            "start record as an Unsigned",
            &stream(&[0x1E, 0x21, 0x05, 0x21, 0x10, 0x1F]),
            Malformed,
        ),
        (
            "octet count as an ENUMERATED",
            &stream(&[0x0E, 0x31, 0x05, 0x91, 0x10, 0x0F]),
            Malformed,
        ),
        (
            "record count as context [1]",
            &stream(&[0x1E, 0x31, 0x05, 0x19, 0x10, 0x1F]),
            Malformed,
        ),
        (
            "start position cut short inside the frame",
            &stream(&[0x0E, 0x32, 0x05, 0x0F]),
            Malformed,
        ),
        ("no access method", FILE_1, Malformed),
        (
            "access method [2]",
            &stream(&[0x2E, 0x31, 0x05, 0x21, 0x10, 0x2F]),
            Malformed,
        ),
        (
            "an octet after the frame",
            &stream(&[0x0E, 0x31, 0x05, 0x21, 0x10, 0x0F, 0x00]),
            Decodes,
        ),
        (
            "a member after the count",
            &stream(&[0x0E, 0x31, 0x05, 0x21, 0x10, 0x21, 0x01, 0x0F]),
            Decodes,
        ),
    ];
    check(decoder!(AtomicReadFileRequest), rows);
}

#[test]
fn atomic_write_file_request() {
    let file = |frame: &[u8]| cat(&[FILE_1, frame]);
    let rows: &[Row<'_>] = &[
        // Stream access: two octets at 5.
        (
            "stream",
            &file(&[0x0E, 0x31, 0x05, 0x62, 0xAA, 0xBB, 0x0F]),
            Decodes,
        ),
        // Record access: two records at 0.
        (
            "record",
            &file(&[0x1E, 0x31, 0x00, 0x21, 0x02, 0x61, 0xAA, 0x61, 0xBB, 0x1F]),
            Decodes,
        ),
        (
            "file identifier as context [0]",
            &[
                0x0C, 0x02, 0x80, 0x00, 0x01, 0x0E, 0x31, 0x05, 0x62, 0xAA, 0xBB, 0x0F,
            ],
            Malformed,
        ),
        ("file identifier cut short", &[0xC4, 0x02], Short),
        (
            "start position as an Unsigned, file data as a CharacterString",
            &file(&[0x0E, 0x21, 0x05, 0x72, 0x00, 0x41, 0x0F]),
            Malformed,
        ),
        (
            "start position as context [0]",
            &file(&[0x0E, 0x09, 0x05, 0x62, 0xAA, 0xBB, 0x0F]),
            Malformed,
        ),
        (
            "file data as a CharacterString",
            &file(&[0x0E, 0x31, 0x05, 0x72, 0x00, 0x41, 0x0F]),
            Malformed,
        ),
        (
            "file data as context [1]",
            &file(&[0x0E, 0x31, 0x05, 0x1A, 0xAA, 0xBB, 0x0F]),
            Malformed,
        ),
        (
            "record count as an ENUMERATED",
            &file(&[0x1E, 0x31, 0x00, 0x91, 0x01, 0x61, 0xAA, 0x1F]),
            Malformed,
        ),
        (
            "a record as an Unsigned",
            &file(&[0x1E, 0x31, 0x00, 0x21, 0x01, 0x21, 0x05, 0x1F]),
            Malformed,
        ),
        (
            "a record as context [0]",
            &file(&[0x1E, 0x31, 0x00, 0x21, 0x01, 0x09, 0x05, 0x1F]),
            Malformed,
        ),
        (
            "the first of two records as an Unsigned, the second missing",
            &file(&[0x1E, 0x31, 0x00, 0x21, 0x02, 0x21, 0x05, 0x1F]),
            Malformed,
        ),
        (
            "fewer records than counted",
            &file(&[0x1E, 0x31, 0x00, 0x21, 0x02, 0x61, 0xAA, 0x1F]),
            Kind::Reject(RejectReason::MISSING_REQUIRED_PARAMETER),
        ),
        (
            "more records than counted",
            &file(&[0x1E, 0x31, 0x00, 0x21, 0x01, 0x61, 0xAA, 0x61, 0xBB, 0x1F]),
            Kind::Reject(RejectReason::TOO_MANY_ARGUMENTS),
        ),
        (
            "an Unsigned after the counted records",
            &file(&[0x1E, 0x31, 0x00, 0x21, 0x01, 0x61, 0xAA, 0x21, 0x05, 0x1F]),
            Kind::Reject(RejectReason::TOO_MANY_ARGUMENTS),
        ),
        (
            "an octet after the frame",
            &file(&[0x0E, 0x31, 0x05, 0x62, 0xAA, 0xBB, 0x0F, 0x00]),
            Decodes,
        ),
        (
            "a member after the file data",
            &file(&[0x0E, 0x31, 0x05, 0x62, 0xAA, 0xBB, 0x21, 0x01, 0x0F]),
            Decodes,
        ),
    ];
    check(decoder!(AtomicWriteFileRequest), rows);
}
