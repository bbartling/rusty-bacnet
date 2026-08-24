use super::*;
use bacnet_types::enums::ErrorCode;

#[test]
fn file_object_creation() {
    let file = FileObject::new(1, "FILE-1", "text/plain").unwrap();
    assert_eq!(file.object_name(), "FILE-1");
    assert_eq!(file.object_identifier().instance_number(), 1);
}

#[test]
fn file_read_object_type() {
    let file = FileObject::new(1, "FILE-1", "text/plain").unwrap();
    let val = file
        .read_property(PropertyIdentifier::OBJECT_TYPE, None)
        .unwrap();
    assert_eq!(val, PropertyValue::Enumerated(ObjectType::FILE.to_raw()));
}

#[test]
fn file_read_object_identifier() {
    let file = FileObject::new(42, "FILE-42", "application/octet-stream").unwrap();
    let val = file
        .read_property(PropertyIdentifier::OBJECT_IDENTIFIER, None)
        .unwrap();
    if let PropertyValue::ObjectIdentifier(oid) = val {
        assert_eq!(oid.instance_number(), 42);
    } else {
        panic!("expected ObjectIdentifier");
    }
}

#[test]
fn file_read_object_name() {
    let file = FileObject::new(1, "MY-FILE", "text/plain").unwrap();
    let val = file
        .read_property(PropertyIdentifier::OBJECT_NAME, None)
        .unwrap();
    assert_eq!(val, PropertyValue::CharacterString("MY-FILE".into()));
}

#[test]
fn file_read_file_type() {
    let file = FileObject::new(1, "FILE-1", "text/csv").unwrap();
    let val = file
        .read_property(PropertyIdentifier::FILE_TYPE, None)
        .unwrap();
    assert_eq!(val, PropertyValue::CharacterString("text/csv".into()));
}

#[test]
fn file_read_file_size_default_zero() {
    let file = FileObject::new(1, "FILE-1", "text/plain").unwrap();
    let val = file
        .read_property(PropertyIdentifier::FILE_SIZE, None)
        .unwrap();
    assert_eq!(val, PropertyValue::Unsigned(0));
}

#[test]
fn file_set_data_updates_file_size() {
    let mut file = FileObject::new(1, "FILE-1", "text/plain").unwrap();
    file.set_data(vec![0x48, 0x65, 0x6C, 0x6C, 0x6F]); // "Hello"
    let val = file
        .read_property(PropertyIdentifier::FILE_SIZE, None)
        .unwrap();
    assert_eq!(val, PropertyValue::Unsigned(5));
    assert_eq!(file.data(), &[0x48, 0x65, 0x6C, 0x6C, 0x6F]);
}

#[test]
fn file_read_archive_default_false() {
    let file = FileObject::new(1, "FILE-1", "text/plain").unwrap();
    let val = file
        .read_property(PropertyIdentifier::ARCHIVE, None)
        .unwrap();
    assert_eq!(val, PropertyValue::Boolean(false));
}

#[test]
fn file_set_and_read_archive() {
    let mut file = FileObject::new(1, "FILE-1", "text/plain").unwrap();
    file.set_archive(true);
    assert!(file.archive());
    let val = file
        .read_property(PropertyIdentifier::ARCHIVE, None)
        .unwrap();
    assert_eq!(val, PropertyValue::Boolean(true));
}

#[test]
fn file_read_read_only_default_false() {
    let file = FileObject::new(1, "FILE-1", "text/plain").unwrap();
    let val = file
        .read_property(PropertyIdentifier::READ_ONLY, None)
        .unwrap();
    assert_eq!(val, PropertyValue::Boolean(false));
}

#[test]
fn file_set_and_read_read_only() {
    let mut file = FileObject::new(1, "FILE-1", "text/plain").unwrap();
    file.set_read_only(true);
    assert!(file.read_only());
    let val = file
        .read_property(PropertyIdentifier::READ_ONLY, None)
        .unwrap();
    assert_eq!(val, PropertyValue::Boolean(true));
}

#[test]
fn file_read_modification_date_default_unspecified() {
    let file = FileObject::new(1, "FILE-1", "text/plain").unwrap();
    let val = file
        .read_property(PropertyIdentifier::MODIFICATION_DATE, None)
        .unwrap();
    if let PropertyValue::List(items) = val {
        assert_eq!(items.len(), 2);
        let unspec_date = Date {
            year: 0xFF,
            month: 0xFF,
            day: 0xFF,
            day_of_week: 0xFF,
        };
        let unspec_time = Time {
            hour: 0xFF,
            minute: 0xFF,
            second: 0xFF,
            hundredths: 0xFF,
        };
        assert_eq!(items[0], PropertyValue::Date(unspec_date));
        assert_eq!(items[1], PropertyValue::Time(unspec_time));
    } else {
        panic!("expected PropertyValue::List");
    }
}

#[test]
fn file_set_and_read_modification_date() {
    let mut file = FileObject::new(1, "FILE-1", "text/plain").unwrap();
    let d = Date {
        year: 126,
        month: 3,
        day: 1,
        day_of_week: 7,
    };
    let t = Time {
        hour: 14,
        minute: 30,
        second: 0,
        hundredths: 0,
    };
    file.set_modification_date(d, t);
    let val = file
        .read_property(PropertyIdentifier::MODIFICATION_DATE, None)
        .unwrap();
    if let PropertyValue::List(items) = val {
        assert_eq!(items[0], PropertyValue::Date(d));
        assert_eq!(items[1], PropertyValue::Time(t));
    } else {
        panic!("expected PropertyValue::List");
    }
}

#[test]
fn file_read_file_access_method_default_stream() {
    let file = FileObject::new(1, "FILE-1", "text/plain").unwrap();
    let val = file
        .read_property(PropertyIdentifier::FILE_ACCESS_METHOD, None)
        .unwrap();
    // stream-access is 1 per the Clause 21 production (#273).
    assert_eq!(
        val,
        PropertyValue::Enumerated(FileAccessMethod::STREAM_ACCESS.to_raw())
    );
    assert_eq!(
        val,
        PropertyValue::Enumerated(1),
        "stream-access enumeration value"
    );
}

#[test]
fn file_read_file_access_method_record() {
    let mut file = FileObject::new(1, "FILE-1", "text/plain").unwrap();
    file.set_file_access_method(FileAccessMethod::RECORD_ACCESS.to_raw());
    let val = file
        .read_property(PropertyIdentifier::FILE_ACCESS_METHOD, None)
        .unwrap();
    // record-access is 0 per the Clause 21 production (#273).
    assert_eq!(
        val,
        PropertyValue::Enumerated(FileAccessMethod::RECORD_ACCESS.to_raw())
    );
    assert_eq!(
        val,
        PropertyValue::Enumerated(0),
        "record-access enumeration value"
    );
}

#[test]
fn file_record_count_unavailable_for_stream() {
    let file = FileObject::new(1, "FILE-1", "text/plain").unwrap();
    let result = file.read_property(PropertyIdentifier::RECORD_COUNT, None);
    assert!(result.is_err());
}

#[test]
fn file_set_records_updates_record_count_and_size() {
    let mut file = FileObject::new(1, "FILE-1", "text/plain").unwrap();
    file.set_file_access_method(FileAccessMethod::RECORD_ACCESS.to_raw());
    file.set_records(vec![vec![0x01, 0x02], vec![0x03, 0x04, 0x05]]);
    let count = file
        .read_property(PropertyIdentifier::RECORD_COUNT, None)
        .unwrap();
    assert_eq!(count, PropertyValue::Unsigned(2));
    let size = file
        .read_property(PropertyIdentifier::FILE_SIZE, None)
        .unwrap();
    assert_eq!(size, PropertyValue::Unsigned(5)); // 2 + 3 bytes
    assert_eq!(file.records().len(), 2);
}

#[test]
fn file_read_status_flags_default() {
    let file = FileObject::new(1, "FILE-1", "text/plain").unwrap();
    let val = file
        .read_property(PropertyIdentifier::STATUS_FLAGS, None)
        .unwrap();
    if let PropertyValue::BitString { unused_bits, data } = val {
        assert_eq!(unused_bits, 4);
        assert_eq!(data, vec![0x00]);
    } else {
        panic!("expected BitString");
    }
}

#[test]
fn file_read_out_of_service_default_false() {
    let file = FileObject::new(1, "FILE-1", "text/plain").unwrap();
    let val = file
        .read_property(PropertyIdentifier::OUT_OF_SERVICE, None)
        .unwrap();
    assert_eq!(val, PropertyValue::Boolean(false));
}

#[test]
fn file_read_reliability_default() {
    let file = FileObject::new(1, "FILE-1", "text/plain").unwrap();
    let val = file
        .read_property(PropertyIdentifier::RELIABILITY, None)
        .unwrap();
    assert_eq!(val, PropertyValue::Enumerated(0));
}

#[test]
fn file_read_description_default_empty() {
    let file = FileObject::new(1, "FILE-1", "text/plain").unwrap();
    let val = file
        .read_property(PropertyIdentifier::DESCRIPTION, None)
        .unwrap();
    assert_eq!(val, PropertyValue::CharacterString(String::new()));
}

#[test]
fn file_write_description() {
    let mut file = FileObject::new(1, "FILE-1", "text/plain").unwrap();
    file.write_property(
        PropertyIdentifier::DESCRIPTION,
        None,
        PropertyValue::CharacterString("A test file".into()),
        None,
    )
    .unwrap();
    let val = file
        .read_property(PropertyIdentifier::DESCRIPTION, None)
        .unwrap();
    assert_eq!(val, PropertyValue::CharacterString("A test file".into()));
}

#[test]
fn file_write_archive() {
    let mut file = FileObject::new(1, "FILE-1", "text/plain").unwrap();
    file.write_property(
        PropertyIdentifier::ARCHIVE,
        None,
        PropertyValue::Boolean(true),
        None,
    )
    .unwrap();
    let val = file
        .read_property(PropertyIdentifier::ARCHIVE, None)
        .unwrap();
    assert_eq!(val, PropertyValue::Boolean(true));
}

#[test]
fn file_write_archive_invalid_type() {
    let mut file = FileObject::new(1, "FILE-1", "text/plain").unwrap();
    let result = file.write_property(
        PropertyIdentifier::ARCHIVE,
        None,
        PropertyValue::Unsigned(1),
        None,
    );
    assert!(result.is_err());
}

#[test]
fn file_write_file_type() {
    let mut file = FileObject::new(1, "FILE-1", "text/plain").unwrap();
    file.write_property(
        PropertyIdentifier::FILE_TYPE,
        None,
        PropertyValue::CharacterString("application/json".into()),
        None,
    )
    .unwrap();
    let val = file
        .read_property(PropertyIdentifier::FILE_TYPE, None)
        .unwrap();
    assert_eq!(
        val,
        PropertyValue::CharacterString("application/json".into())
    );
}

#[test]
fn file_write_out_of_service() {
    let mut file = FileObject::new(1, "FILE-1", "text/plain").unwrap();
    file.write_property(
        PropertyIdentifier::OUT_OF_SERVICE,
        None,
        PropertyValue::Boolean(true),
        None,
    )
    .unwrap();
    let val = file
        .read_property(PropertyIdentifier::OUT_OF_SERVICE, None)
        .unwrap();
    assert_eq!(val, PropertyValue::Boolean(true));
}

#[test]
fn file_write_read_only_denied() {
    let mut file = FileObject::new(1, "FILE-1", "text/plain").unwrap();
    let result = file.write_property(
        PropertyIdentifier::READ_ONLY,
        None,
        PropertyValue::Boolean(true),
        None,
    );
    assert!(result.is_err());
}

#[test]
fn file_write_file_size_denied() {
    let mut file = FileObject::new(1, "FILE-1", "text/plain").unwrap();
    let result = file.write_property(
        PropertyIdentifier::FILE_SIZE,
        None,
        PropertyValue::Unsigned(100),
        None,
    );
    assert!(result.is_err());
}

#[test]
fn file_property_list_stream() {
    let file = FileObject::new(1, "FILE-1", "text/plain").unwrap();
    let props = file.property_list();
    assert!(props.contains(&PropertyIdentifier::OBJECT_IDENTIFIER));
    assert!(props.contains(&PropertyIdentifier::OBJECT_NAME));
    assert!(props.contains(&PropertyIdentifier::OBJECT_TYPE));
    assert!(props.contains(&PropertyIdentifier::FILE_TYPE));
    assert!(props.contains(&PropertyIdentifier::FILE_SIZE));
    assert!(props.contains(&PropertyIdentifier::MODIFICATION_DATE));
    assert!(props.contains(&PropertyIdentifier::ARCHIVE));
    assert!(props.contains(&PropertyIdentifier::READ_ONLY));
    assert!(props.contains(&PropertyIdentifier::FILE_ACCESS_METHOD));
    assert!(props.contains(&PropertyIdentifier::STATUS_FLAGS));
    assert!(props.contains(&PropertyIdentifier::OUT_OF_SERVICE));
    assert!(props.contains(&PropertyIdentifier::RELIABILITY));
    // RECORD_COUNT should NOT be in property list for stream-access files
    assert!(!props.contains(&PropertyIdentifier::RECORD_COUNT));
}

#[test]
fn file_property_list_record_access() {
    let mut file = FileObject::new(1, "FILE-1", "text/plain").unwrap();
    file.set_file_access_method(FileAccessMethod::RECORD_ACCESS.to_raw());
    let props = file.property_list();
    assert!(props.contains(&PropertyIdentifier::RECORD_COUNT));
}

#[test]
fn file_unknown_property_error() {
    let file = FileObject::new(1, "FILE-1", "text/plain").unwrap();
    let result = file.read_property(PropertyIdentifier::PRESENT_VALUE, None);
    assert!(result.is_err());
    if let Err(Error::Protocol { code, .. }) = result {
        assert_eq!(code, ErrorCode::UNKNOWN_PROPERTY.to_raw() as u32);
    } else {
        panic!("expected Protocol error");
    }
}

// ---------------------------------------------------------------------------
// FileStorage (#397) — the Clause 14 service data behind the object.
// ---------------------------------------------------------------------------

fn protocol_pair(err: Error) -> (u32, u32) {
    match err {
        Error::Protocol { class, code } => (class, code),
        other => panic!("expected protocol error, got {other:?}"),
    }
}

fn file_full_pair() -> (u32, u32) {
    (
        ErrorClass::OBJECT.to_raw() as u32,
        ErrorCode::FILE_FULL.to_raw() as u32,
    )
}

fn invalid_method_pair() -> (u32, u32) {
    (
        ErrorClass::SERVICES.to_raw() as u32,
        ErrorCode::INVALID_FILE_ACCESS_METHOD.to_raw() as u32,
    )
}

fn invalid_start_pair() -> (u32, u32) {
    (
        ErrorClass::SERVICES.to_raw() as u32,
        ErrorCode::INVALID_FILE_START_POSITION.to_raw() as u32,
    )
}

fn stream_file() -> FileObject {
    let mut file = FileObject::new(1, "FILE-1", "text/plain").unwrap();
    file.set_data(vec![1, 2, 3, 4, 5, 6, 7, 8]);
    file
}

fn record_file() -> FileObject {
    let mut file = FileObject::new(1, "FILE-1", "text/plain").unwrap();
    file.set_file_access_method(FileAccessMethod::RECORD_ACCESS.to_raw());
    file.set_records(vec![vec![0xAA, 0xBB], vec![0xCC, 0xDD], vec![0xEE]]);
    file
}

#[test]
fn storage_stream_write_then_read_round_trips() {
    let mut file = stream_file();
    assert_eq!(
        file.write_stream(FileWriteStart::At(2), &[0xAA, 0xBB])
            .unwrap(),
        2
    );
    let read = file.read_stream(2, 2).unwrap();
    assert_eq!(read.data, vec![0xAA, 0xBB]);
    assert!(!read.end_of_file);
    assert_eq!(file.file_size(), 8);
    assert_eq!(
        file.write_stream(FileWriteStart::Append, &[0x99]).unwrap(),
        8
    );
    assert_eq!(file.data(), &[1, 2, 0xAA, 0xBB, 5, 6, 7, 8, 0x99]);
    assert_eq!(file.file_size(), 9);
}

#[test]
fn storage_stream_read_boundaries() {
    let file = stream_file();
    let at_end = file.read_stream(8, 4).unwrap();
    assert!(at_end.data.is_empty());
    assert!(at_end.end_of_file);
    assert_eq!(
        protocol_pair(file.read_stream(9, 1).unwrap_err()),
        invalid_start_pair()
    );
    let short = file.read_stream(6, u64::MAX).unwrap();
    assert_eq!(short.data, vec![7, 8]);
    assert!(short.end_of_file);
}

#[test]
fn storage_stream_growth_cap_is_file_full_and_leaves_data_unchanged() {
    let mut file = stream_file();
    file.set_max_file_size(4);
    assert_eq!(
        protocol_pair(
            file.write_stream(FileWriteStart::At(8), &[0x01])
                .unwrap_err()
        ),
        file_full_pair()
    );
    assert_eq!(file.data(), &[1, 2, 3, 4, 5, 6, 7, 8]);
    assert_eq!(file.file_size(), 8);
    // Preloaded contents past the cap are still writable in place.
    file.write_stream(FileWriteStart::At(0), &[0xF0, 0xF1])
        .unwrap();
    assert_eq!(file.data(), &[0xF0, 0xF1, 3, 4, 5, 6, 7, 8]);
    assert_eq!(
        protocol_pair(
            file.write_stream(FileWriteStart::At(u64::MAX), &[0x01])
                .unwrap_err()
        ),
        file_full_pair(),
        "offset overflow is reported as FILE_FULL"
    );
}

#[test]
fn storage_record_write_then_read_round_trips() {
    let mut file = record_file();
    assert_eq!(
        file.write_records(FileWriteStart::At(1), &[vec![0x01, 0x02, 0x03]])
            .unwrap(),
        1
    );
    assert_eq!(file.records()[1], vec![0x01, 0x02, 0x03]);
    assert_eq!(file.file_size(), 6);
    assert_eq!(
        file.read_property(PropertyIdentifier::RECORD_COUNT, None)
            .unwrap(),
        PropertyValue::Unsigned(3)
    );
    assert_eq!(
        file.write_records(FileWriteStart::Append, &[vec![0x77]])
            .unwrap(),
        3
    );
    assert_eq!(file.records().len(), 4);
    assert_eq!(file.file_size(), 7);
    let read = file.read_records(3, 5).unwrap();
    assert_eq!(read.records, vec![vec![0x77]]);
    assert!(read.end_of_file);
    assert_eq!(
        protocol_pair(file.read_records(5, 1).unwrap_err()),
        invalid_start_pair()
    );
}

#[test]
fn storage_record_caps_are_file_full_and_leave_records_unchanged() {
    let mut file = record_file();
    file.set_max_record_count(2);
    assert_eq!(
        protocol_pair(
            file.write_records(FileWriteStart::At(3), &[vec![0x01]])
                .unwrap_err()
        ),
        file_full_pair()
    );
    assert_eq!(file.records().len(), 3);
    assert_eq!(file.file_size(), 5);
    // In-place replacement of preloaded records is not growth.
    file.write_records(FileWriteStart::At(2), &[vec![0x0E, 0x0F]])
        .unwrap();
    assert_eq!(file.records()[2], vec![0x0E, 0x0F]);

    let mut file = record_file();
    file.set_max_file_size(5);
    assert_eq!(
        protocol_pair(
            file.write_records(FileWriteStart::Append, &[vec![0x01]])
                .unwrap_err()
        ),
        file_full_pair(),
        "octet cap applies to record payloads"
    );
    assert_eq!(file.records().len(), 3);
    file.write_records(FileWriteStart::At(0), &[vec![0x10, 0x11]])
        .unwrap();
    assert_eq!(file.file_size(), 5);
}

#[test]
fn storage_refuses_the_other_access_method() {
    let mut stream = stream_file();
    assert_eq!(
        protocol_pair(stream.read_records(0, 1).unwrap_err()),
        invalid_method_pair()
    );
    assert_eq!(
        protocol_pair(
            stream
                .write_records(FileWriteStart::At(0), &[vec![1]])
                .unwrap_err()
        ),
        invalid_method_pair()
    );
    let mut record = record_file();
    assert_eq!(
        protocol_pair(record.read_stream(0, 1).unwrap_err()),
        invalid_method_pair()
    );
    assert_eq!(
        protocol_pair(
            record
                .write_stream(FileWriteStart::At(0), &[1])
                .unwrap_err()
        ),
        invalid_method_pair()
    );
    assert_eq!(stream.data(), &[1, 2, 3, 4, 5, 6, 7, 8]);
    assert_eq!(record.records().len(), 3);
}

#[test]
fn storage_caps_default_and_clamp_to_integer_range() {
    let mut file = FileObject::new(1, "FILE-1", "text/plain").unwrap();
    assert_eq!(file.max_file_size(), DEFAULT_MAX_FILE_SIZE);
    assert_eq!(file.max_record_count(), DEFAULT_MAX_RECORD_COUNT);
    file.set_max_file_size(u64::MAX);
    file.set_max_record_count(u64::MAX);
    assert_eq!(file.max_file_size(), i32::MAX as u64);
    assert_eq!(file.max_record_count(), i32::MAX as u64);
}

struct NoStorageFile;

impl BACnetObject for NoStorageFile {
    fn object_identifier(&self) -> ObjectIdentifier {
        ObjectIdentifier::new(ObjectType::FILE, 7).unwrap()
    }

    fn object_name(&self) -> &str {
        "NO-STORAGE"
    }

    fn read_property(
        &self,
        _property: PropertyIdentifier,
        _array_index: Option<u32>,
    ) -> Result<PropertyValue, Error> {
        Err(common::unknown_property_error())
    }

    fn write_property(
        &mut self,
        _property: PropertyIdentifier,
        _array_index: Option<u32>,
        _value: PropertyValue,
        _priority: Option<u8>,
    ) -> Result<(), Error> {
        Err(common::write_access_denied_error())
    }

    fn property_list(&self) -> Cow<'static, [PropertyIdentifier]> {
        Cow::Borrowed(&[])
    }
}

#[test]
fn storage_hooks_default_to_none_and_file_object_opts_in() {
    let mut none = NoStorageFile;
    assert!(none.file_storage_internal().is_none());
    assert!(none.file_storage_internal_mut().is_none());
    let mut file = stream_file();
    assert!(file.file_storage_internal().is_some());
    assert!(file.file_storage_internal_mut().is_some());
    assert!(!file
        .property_list()
        .iter()
        .any(|p| *p == PropertyIdentifier::from_raw(65)));
}
