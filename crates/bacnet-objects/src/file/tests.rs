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
