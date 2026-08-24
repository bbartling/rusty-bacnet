//! A File-typed object without a storage hook (#397): the handlers report
//! it as SERVICES / FILE_ACCESS_DENIED (Clause 18, "a file that is currently
//! locked or otherwise not accessible") directly after the lookup — the
//! Clause 14.1 / 14.2 Service Procedures decide "currently inaccessible for
//! another reason" in their first step, ahead of the read-only and
//! access-method gates — and never read it as empty. The same module pins
//! the write handler's fail-closed Read_Only gate and the record cap's tie
//! to the decoder ceiling.

use super::file_access_method::{
    assert_file_access_denied, read_wire_for, write_wire_for, SENTINEL,
};
use super::*;
use bacnet_services::file::{FileAccessMethod, FileWriteAccessMethod};
use bacnet_types::enums::FileAccessMethod as ObjectFileAccessMethod;
use std::borrow::Cow;

/// A File object that models its properties but exposes no contents.
struct HookLessFile;

impl BACnetObject for HookLessFile {
    fn object_identifier(&self) -> ObjectIdentifier {
        ObjectIdentifier::new(ObjectType::FILE, 5).unwrap()
    }

    fn object_name(&self) -> &str {
        "HOOKLESS"
    }

    fn read_property(
        &self,
        property: PropertyIdentifier,
        _array_index: Option<u32>,
    ) -> Result<PropertyValue, Error> {
        match property {
            p if p == PropertyIdentifier::READ_ONLY => Ok(PropertyValue::Boolean(false)),
            p if p == PropertyIdentifier::FILE_ACCESS_METHOD => Ok(PropertyValue::Enumerated(
                ObjectFileAccessMethod::STREAM_ACCESS.to_raw(),
            )),
            _ => Err(Error::Protocol {
                class: ErrorClass::PROPERTY.to_raw() as u32,
                code: ErrorCode::UNKNOWN_PROPERTY.to_raw() as u32,
            }),
        }
    }

    fn write_property(
        &mut self,
        _property: PropertyIdentifier,
        _array_index: Option<u32>,
        _value: PropertyValue,
        _priority: Option<u8>,
    ) -> Result<(), Error> {
        Err(Error::Protocol {
            class: ErrorClass::PROPERTY.to_raw() as u32,
            code: ErrorCode::WRITE_ACCESS_DENIED.to_raw() as u32,
        })
    }

    fn property_list(&self) -> Cow<'static, [PropertyIdentifier]> {
        Cow::Borrowed(&[])
    }
}

fn oid() -> ObjectIdentifier {
    ObjectIdentifier::new(ObjectType::FILE, 5).unwrap()
}

#[test]
fn file_object_without_storage_hook_is_file_access_denied() {
    let mut db = ObjectDatabase::new();
    db.add(Box::new(HookLessFile)).unwrap();

    let mut buf = BytesMut::from(SENTINEL);
    let result = handle_atomic_read_file(
        &db,
        &read_wire_for(
            oid(),
            FileAccessMethod::Stream {
                file_start_position: 0,
                requested_octet_count: 4,
            },
        ),
        &mut buf,
    );
    assert_file_access_denied(result, "read of a hook-less File");
    assert_eq!(&buf[..], SENTINEL, "refused read must not touch the buffer");

    let mut buf = BytesMut::from(SENTINEL);
    let result = handle_atomic_write_file(
        &mut db,
        &write_wire_for(
            oid(),
            FileWriteAccessMethod::Stream {
                file_start_position: 0,
                file_data: vec![0x01],
            },
        ),
        &mut buf,
    );
    assert_file_access_denied(result, "write to a hook-less File");
    assert_eq!(
        &buf[..],
        SENTINEL,
        "refused write must not touch the buffer"
    );

    // Inaccessible is decided before the access-method gate: a mismatched
    // method on a hook-less File still draws FILE_ACCESS_DENIED.
    let mut buf = BytesMut::from(SENTINEL);
    let result = handle_atomic_read_file(
        &db,
        &read_wire_for(
            oid(),
            FileAccessMethod::Record {
                file_start_record: 0,
                requested_record_count: 1,
            },
        ),
        &mut buf,
    );
    assert_file_access_denied(result, "record read of a hook-less STREAM_ACCESS File");
    assert_eq!(&buf[..], SENTINEL);
    let mut buf = BytesMut::from(SENTINEL);
    let result = handle_atomic_write_file(
        &mut db,
        &write_wire_for(
            oid(),
            FileWriteAccessMethod::Record {
                file_start_record: 0,
                record_count: 1,
                file_record_data: vec![vec![0x01]],
            },
        ),
        &mut buf,
    );
    assert_file_access_denied(result, "record write to a hook-less STREAM_ACCESS File");
    assert_eq!(&buf[..], SENTINEL);
}

/// `FileObject`'s record cap must never exceed the largest SEQUENCE OF the
/// service decoders accept, or a file grown to the cap could not be read
/// back by this workspace's own client.
#[test]
fn record_cap_never_exceeds_the_decoder_ceiling() {
    assert!(
        bacnet_objects::file::DEFAULT_MAX_RECORD_COUNT
            <= bacnet_services::common::MAX_DECODED_ITEMS as u64
    );
}

// ──────────────────────────────────────────────────────────────────────────
// The handler's access-method gate is normative on its own: a storage that
// accepts either method is still never reached with the wrong one.
// ──────────────────────────────────────────────────────────────────────────

use bacnet_objects::file::{FileRecordRead, FileStorage, FileStreamRead, FileWriteStart};
use std::sync::atomic::{AtomicUsize, Ordering};

static LAX_WRITES: AtomicUsize = AtomicUsize::new(0);

/// Declares STREAM_ACCESS but whose storage would happily take records.
struct LaxFile;

impl FileStorage for LaxFile {
    fn read_stream(&self, _start: u64, _count: u64) -> Result<FileStreamRead, Error> {
        Ok(FileStreamRead {
            data: vec![0x42],
            end_of_file: true,
        })
    }

    fn write_stream(&mut self, _start: FileWriteStart, _data: &[u8]) -> Result<u64, Error> {
        LAX_WRITES.fetch_add(1, Ordering::SeqCst);
        Ok(0)
    }

    fn read_records(&self, _start: u64, _count: u64) -> Result<FileRecordRead, Error> {
        Ok(FileRecordRead {
            records: vec![vec![0x42]],
            end_of_file: true,
        })
    }

    fn write_records(
        &mut self,
        _start: FileWriteStart,
        _records: &[Vec<u8>],
    ) -> Result<u64, Error> {
        LAX_WRITES.fetch_add(1, Ordering::SeqCst);
        Ok(0)
    }
}

impl BACnetObject for LaxFile {
    fn object_identifier(&self) -> ObjectIdentifier {
        oid()
    }

    fn object_name(&self) -> &str {
        "LAX"
    }

    fn read_property(
        &self,
        property: PropertyIdentifier,
        array_index: Option<u32>,
    ) -> Result<PropertyValue, Error> {
        HookLessFile.read_property(property, array_index)
    }

    fn write_property(
        &mut self,
        property: PropertyIdentifier,
        array_index: Option<u32>,
        value: PropertyValue,
        priority: Option<u8>,
    ) -> Result<(), Error> {
        HookLessFile.write_property(property, array_index, value, priority)
    }

    fn property_list(&self) -> Cow<'static, [PropertyIdentifier]> {
        Cow::Borrowed(&[])
    }

    fn file_storage_internal(&self) -> Option<&dyn FileStorage> {
        Some(self)
    }

    fn file_storage_internal_mut(&mut self) -> Option<&mut dyn FileStorage> {
        Some(self)
    }
}

#[test]
fn handler_access_method_gate_protects_lax_storage() {
    use super::file_access_method::assert_invalid_access;

    let mut db = ObjectDatabase::new();
    db.add(Box::new(LaxFile)).unwrap();
    let before = LAX_WRITES.load(Ordering::SeqCst);

    let mut buf = BytesMut::from(SENTINEL);
    let result = handle_atomic_write_file(
        &mut db,
        &write_wire_for(
            oid(),
            FileWriteAccessMethod::Record {
                file_start_record: 0,
                record_count: 1,
                file_record_data: vec![vec![0x01]],
            },
        ),
        &mut buf,
    );
    assert_invalid_access(result, "record write to a STREAM_ACCESS lax file");
    assert_eq!(
        &buf[..],
        SENTINEL,
        "refused write must not touch the buffer"
    );
    assert_eq!(
        LAX_WRITES.load(Ordering::SeqCst),
        before,
        "storage must not be reached"
    );

    let mut buf = BytesMut::from(SENTINEL);
    let result = handle_atomic_read_file(
        &db,
        &read_wire_for(
            oid(),
            FileAccessMethod::Record {
                file_start_record: 0,
                requested_record_count: 1,
            },
        ),
        &mut buf,
    );
    assert_invalid_access(result, "record read of a STREAM_ACCESS lax file");
    assert_eq!(&buf[..], SENTINEL);

    // The matching method does reach the storage.
    handle_atomic_write_file(
        &mut db,
        &write_wire_for(
            oid(),
            FileWriteAccessMethod::Stream {
                file_start_position: 0,
                file_data: vec![0x01],
            },
        ),
        &mut BytesMut::new(),
    )
    .expect("matching stream write reaches the storage");
    assert_eq!(LAX_WRITES.load(Ordering::SeqCst), before + 1);
}

// ──────────────────────────────────────────────────────────────────────────
// The Read_Only gate fails closed: a File whose Read_Only cannot be read
// is treated as read-only, and its storage is never reached.
// ──────────────────────────────────────────────────────────────────────────

static OPAQUE_WRITES: AtomicUsize = AtomicUsize::new(0);

/// Owns stream storage but answers UNKNOWN_PROPERTY for Read_Only.
struct OpaqueReadOnlyFile;

impl FileStorage for OpaqueReadOnlyFile {
    fn read_stream(&self, _start: u64, _count: u64) -> Result<FileStreamRead, Error> {
        Ok(FileStreamRead {
            data: vec![0x42],
            end_of_file: true,
        })
    }

    fn write_stream(&mut self, _start: FileWriteStart, _data: &[u8]) -> Result<u64, Error> {
        OPAQUE_WRITES.fetch_add(1, Ordering::SeqCst);
        Ok(0)
    }
}

impl BACnetObject for OpaqueReadOnlyFile {
    fn object_identifier(&self) -> ObjectIdentifier {
        oid()
    }

    fn object_name(&self) -> &str {
        "OPAQUE"
    }

    fn read_property(
        &self,
        property: PropertyIdentifier,
        _array_index: Option<u32>,
    ) -> Result<PropertyValue, Error> {
        match property {
            p if p == PropertyIdentifier::FILE_ACCESS_METHOD => Ok(PropertyValue::Enumerated(
                ObjectFileAccessMethod::STREAM_ACCESS.to_raw(),
            )),
            _ => Err(Error::Protocol {
                class: ErrorClass::PROPERTY.to_raw() as u32,
                code: ErrorCode::UNKNOWN_PROPERTY.to_raw() as u32,
            }),
        }
    }

    fn write_property(
        &mut self,
        property: PropertyIdentifier,
        array_index: Option<u32>,
        value: PropertyValue,
        priority: Option<u8>,
    ) -> Result<(), Error> {
        HookLessFile.write_property(property, array_index, value, priority)
    }

    fn property_list(&self) -> Cow<'static, [PropertyIdentifier]> {
        Cow::Borrowed(&[])
    }

    fn file_storage_internal(&self) -> Option<&dyn FileStorage> {
        Some(self)
    }

    fn file_storage_internal_mut(&mut self) -> Option<&mut dyn FileStorage> {
        Some(self)
    }
}

#[test]
fn unreadable_read_only_is_treated_as_read_only() {
    let mut db = ObjectDatabase::new();
    db.add(Box::new(OpaqueReadOnlyFile)).unwrap();
    let before = OPAQUE_WRITES.load(Ordering::SeqCst);

    let mut buf = BytesMut::from(SENTINEL);
    let result = handle_atomic_write_file(
        &mut db,
        &write_wire_for(
            oid(),
            FileWriteAccessMethod::Stream {
                file_start_position: 0,
                file_data: vec![0xFF],
            },
        ),
        &mut buf,
    );
    assert_file_access_denied(result, "write to a File with unreadable Read_Only");
    assert_eq!(
        &buf[..],
        SENTINEL,
        "refused write must not touch the buffer"
    );
    assert_eq!(
        OPAQUE_WRITES.load(Ordering::SeqCst),
        before,
        "storage must not be reached"
    );

    // Reads do not consult Read_Only and still work.
    let mut buf = BytesMut::new();
    handle_atomic_read_file(
        &db,
        &read_wire_for(
            oid(),
            FileAccessMethod::Stream {
                file_start_position: 0,
                requested_octet_count: 1,
            },
        ),
        &mut buf,
    )
    .expect("read of the opaque file");
}
