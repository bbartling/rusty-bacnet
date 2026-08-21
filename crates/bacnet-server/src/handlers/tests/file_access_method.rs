//! Access-method cross-checking for AtomicReadFile / AtomicWriteFile
//! (#287): a request whose access method differs from the File object's
//! declared File_Access_Method (Clause 12.13) must be refused with
//! SERVICES / INVALID_FILE_ACCESS_METHOD (Clauses 14.1, 14.2, 18) before
//! any ACK is encoded or any object state is mutated.
//!
//! The request CHOICE tags (stream [0], record [1]) are deliberately not
//! compared against the property's BACnetFileAccessMethod enumeration
//! (record-access = 0, stream-access = 1); the mapping here is semantic.

use super::*;
use bacnet_objects::file::FileObject;
use bacnet_services::file::{
    AtomicReadFileAck, AtomicReadFileRequest, AtomicWriteFileAck, AtomicWriteFileRequest,
    FileAccessMethod, FileReadAckMethod, FileWriteAccessMethod,
};
use bacnet_types::enums::FileAccessMethod as ObjectFileAccessMethod;

const SENTINEL: &[u8] = &[0xDE, 0xAD, 0xBE, 0xEF];

fn stream_file_db() -> ObjectDatabase {
    let mut db = ObjectDatabase::new();
    let mut file = FileObject::new(1, "FILE-1", "text/plain").unwrap();
    file.set_data(vec![1, 2, 3, 4, 5, 6, 7, 8]);
    db.add(Box::new(file)).unwrap();
    db
}

fn record_file_db() -> ObjectDatabase {
    let mut db = ObjectDatabase::new();
    let mut file = FileObject::new(1, "FILE-1", "text/plain").unwrap();
    file.set_file_access_method(ObjectFileAccessMethod::RECORD_ACCESS.to_raw());
    file.set_records(vec![vec![0xAA, 0xBB], vec![0xCC, 0xDD], vec![0xEE]]);
    db.add(Box::new(file)).unwrap();
    db
}

fn file_oid() -> ObjectIdentifier {
    ObjectIdentifier::new(ObjectType::FILE, 1).unwrap()
}

fn read_wire(access: FileAccessMethod) -> Vec<u8> {
    let request = AtomicReadFileRequest {
        file_identifier: file_oid(),
        access,
    };
    let mut buf = BytesMut::new();
    request.encode(&mut buf);
    buf.to_vec()
}

fn write_wire(access: FileWriteAccessMethod) -> Vec<u8> {
    let request = AtomicWriteFileRequest {
        file_identifier: file_oid(),
        access,
    };
    let mut buf = BytesMut::new();
    request.encode(&mut buf);
    buf.to_vec()
}

fn assert_invalid_access(result: Result<(), Error>, context: &str) {
    match result.expect_err(&format!("{context}: request must be refused")) {
        Error::Protocol { class, code } => {
            assert_eq!(
                class,
                ErrorClass::SERVICES.to_raw() as u32,
                "{context}: wrong error class"
            );
            assert_eq!(
                code,
                ErrorCode::INVALID_FILE_ACCESS_METHOD.to_raw() as u32,
                "{context}: wrong error code"
            );
        }
        other => panic!("{context}: expected SERVICES/INVALID_FILE_ACCESS_METHOD, got {other:?}"),
    }
}

// ──────────────────────────────────────────────────────────────────────────
// Mismatch matrix (#287) — all four directions refuse with the exact
// Clause 14 error, leaving the response buffer untouched.
// ──────────────────────────────────────────────────────────────────────────

#[test]
fn read_stream_against_record_access_file_is_refused() {
    let db = record_file_db();
    let mut buf = BytesMut::from(SENTINEL);
    let result = handle_atomic_read_file(
        &db,
        &read_wire(FileAccessMethod::Stream {
            file_start_position: 0,
            requested_octet_count: 4,
        }),
        &mut buf,
    );
    assert_invalid_access(result, "read stream vs RECORD_ACCESS");
    assert_eq!(
        &buf[..],
        SENTINEL,
        "refused read must not touch the response buffer"
    );
}

#[test]
fn read_record_against_stream_access_file_is_refused() {
    let db = stream_file_db();
    let mut buf = BytesMut::from(SENTINEL);
    let result = handle_atomic_read_file(
        &db,
        &read_wire(FileAccessMethod::Record {
            file_start_record: 0,
            requested_record_count: 2,
        }),
        &mut buf,
    );
    assert_invalid_access(result, "read record vs STREAM_ACCESS");
    assert_eq!(
        &buf[..],
        SENTINEL,
        "refused read must not touch the response buffer"
    );
}

#[test]
fn write_stream_against_record_access_file_is_refused() {
    let mut db = record_file_db();
    let mut buf = BytesMut::from(SENTINEL);
    let result = handle_atomic_write_file(
        &mut db,
        &write_wire(FileWriteAccessMethod::Stream {
            file_start_position: 0,
            file_data: vec![0x01, 0x02],
        }),
        &mut buf,
    );
    assert_invalid_access(result, "write stream vs RECORD_ACCESS");
    assert_eq!(
        &buf[..],
        SENTINEL,
        "refused write must not touch the response buffer"
    );
}

#[test]
fn write_record_against_stream_access_file_is_refused() {
    let mut db = stream_file_db();
    let mut buf = BytesMut::from(SENTINEL);
    let result = handle_atomic_write_file(
        &mut db,
        &write_wire(FileWriteAccessMethod::Record {
            file_start_record: 0,
            record_count: 1,
            file_record_data: vec![vec![0x01, 0x02]],
        }),
        &mut buf,
    );
    assert_invalid_access(result, "write record vs STREAM_ACCESS");
    assert_eq!(
        &buf[..],
        SENTINEL,
        "refused write must not touch the response buffer"
    );
}

// ──────────────────────────────────────────────────────────────────────────
// No mutation on mismatched writes — observable File state is unchanged.
// ──────────────────────────────────────────────────────────────────────────

#[test]
fn mismatched_write_leaves_record_file_state_unchanged() {
    let mut db = record_file_db();
    let result = handle_atomic_write_file(
        &mut db,
        &write_wire(FileWriteAccessMethod::Stream {
            file_start_position: 0,
            file_data: vec![0x01, 0x02, 0x03],
        }),
        &mut BytesMut::new(),
    );
    assert_invalid_access(result, "write stream vs RECORD_ACCESS");

    let object = db.get(&file_oid()).unwrap();
    let size = object
        .read_property(PropertyIdentifier::FILE_SIZE, None)
        .unwrap();
    assert_eq!(size, PropertyValue::Unsigned(5), "FILE_SIZE changed");
    let count = object
        .read_property(PropertyIdentifier::RECORD_COUNT, None)
        .unwrap();
    assert_eq!(count, PropertyValue::Unsigned(3), "RECORD_COUNT changed");
}

#[test]
fn mismatched_write_leaves_stream_file_state_unchanged() {
    let mut db = stream_file_db();
    let result = handle_atomic_write_file(
        &mut db,
        &write_wire(FileWriteAccessMethod::Record {
            file_start_record: 0,
            record_count: 1,
            file_record_data: vec![vec![0x01, 0x02]],
        }),
        &mut BytesMut::new(),
    );
    assert_invalid_access(result, "write record vs STREAM_ACCESS");

    let object = db.get(&file_oid()).unwrap();
    let size = object
        .read_property(PropertyIdentifier::FILE_SIZE, None)
        .unwrap();
    assert_eq!(size, PropertyValue::Unsigned(8), "FILE_SIZE changed");
}

// ──────────────────────────────────────────────────────────────────────────
// Matched-method smoke coverage — the validator passes valid combinations
// through to the existing success paths.
// ──────────────────────────────────────────────────────────────────────────

#[test]
fn matched_stream_read_still_succeeds() {
    let db = stream_file_db();
    let mut buf = BytesMut::new();
    handle_atomic_read_file(
        &db,
        &read_wire(FileAccessMethod::Stream {
            file_start_position: 2,
            requested_octet_count: 4,
        }),
        &mut buf,
    )
    .expect("matched stream read must succeed");
    let ack = AtomicReadFileAck::decode(&buf).unwrap();
    match ack.access {
        FileReadAckMethod::Stream {
            file_start_position,
            file_data: _,
        } => {
            assert_eq!(file_start_position, 2);
            // Data content is not asserted here: FileObject does not yet
            // expose File_Data (property 65) through read_property, so the
            // pre-existing success path returns empty octets. That storage
            // gap is tracked separately from #287.
        }
        other => panic!("expected stream ACK method, got {other:?}"),
    }
}

#[test]
fn matched_record_read_still_succeeds() {
    let db = record_file_db();
    let mut buf = BytesMut::new();
    handle_atomic_read_file(
        &db,
        &read_wire(FileAccessMethod::Record {
            file_start_record: 1,
            requested_record_count: 2,
        }),
        &mut buf,
    )
    .expect("matched record read must succeed");
    let ack = AtomicReadFileAck::decode(&buf).unwrap();
    assert!(matches!(
        ack.access,
        bacnet_services::file::FileReadAckMethod::Record { .. }
    ));
}

#[test]
fn matched_record_write_still_succeeds() {
    let mut db = record_file_db();
    let mut buf = BytesMut::new();
    handle_atomic_write_file(
        &mut db,
        &write_wire(FileWriteAccessMethod::Record {
            file_start_record: 7,
            record_count: 1,
            file_record_data: vec![vec![0x01]],
        }),
        &mut buf,
    )
    .expect("matched record write must succeed");
    let ack = AtomicWriteFileAck::decode(&buf).unwrap();
    assert!(matches!(
        ack.access,
        bacnet_services::file::FileWriteAckMethod::Record {
            file_start_record: 7
        }
    ));
}

// ──────────────────────────────────────────────────────────────────────────
// Fail-closed on an unsupported File_Access_Method raw value — the object
// surface already accepts arbitrary raw values via set_file_access_method,
// so no production API expansion is needed to represent this state.
// ──────────────────────────────────────────────────────────────────────────

#[test]
fn unknown_access_method_raw_value_fails_closed() {
    let mut db = ObjectDatabase::new();
    let mut file = FileObject::new(1, "FILE-1", "text/plain").unwrap();
    file.set_file_access_method(99);
    db.add(Box::new(file)).unwrap();

    let mut buf = BytesMut::new();
    let result = handle_atomic_read_file(
        &db,
        &read_wire(FileAccessMethod::Stream {
            file_start_position: 0,
            requested_octet_count: 4,
        }),
        &mut buf,
    );
    assert_invalid_access(result, "unknown raw access method");
    assert_eq!(&buf[..], &[], "buffer must stay empty");
}
