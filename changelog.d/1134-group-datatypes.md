---
section: Fixed
---
- **Breaking Group List_Of_Group_Members and Present_Value (wire and Rust
  API):** the Group object (type 11) serves both lists in their Table 12-17
  datatypes, and Present_Value is rebuilt from the members on every read
  (#1134).
  - A List_Of_Group_Members element is a ReadAccessSpecification: the object
    under `[0]`, then its property references inside `[1]`. It used to go out
    as a bare application-tagged object identifier with no properties.
  - A Present_Value element is a ReadAccessResult, one per member, read as
    ReadPropertyMultiple reads that specification: ALL, REQUIRED and OPTIONAL
    expand, a property that fails to read carries its error class and code
    inside `[5]`, and a member naming an object that isn't in this device's
    database gets OBJECT / UNKNOWN_OBJECT for each reference. The server
    builds it under the request's database guard for ReadProperty,
    ReadPropertyMultiple (RPM ALL included) and ReadRange. It used to serve
    whatever values the application had stored.
  - `GroupObject::add_member` takes a `ReadAccessSpecification` and returns
    `Result`,
    refusing with PROPERTY / VALUE_OUT_OF_RANGE a member with no property
    references and one that names a Group or Global Group and selects its
    Present_Value, directly or through ALL or REQUIRED. The public
    `list_of_group_members` and `present_value` fields are gone: `members()`
    reads the list, and a direct read of the object alone returns an empty
    Present_Value. An array index on either list fails with PROPERTY /
    PROPERTY_IS_NOT_AN_ARRAY in the object as in the services.
  - **Moved (Rust API):** `PropertyReference` (from
    `bacnet_services::common`) and `ReadAccessSpecification` (from
    `bacnet_services::rpm`) now live in `bacnet_types::constructed`, like the
    other Clause 21 types an object stores. Their `encode`/`decode` methods
    are replaced by `encode_property_reference`, `decode_property_reference`,
    `encode_read_access_specification` and `decode_read_access_specification`
    in `bacnet_encoding::constructed`, which the ReadPropertyMultiple, COV and
    Audit codecs use. There is no re-export from the old paths, so update
    imports. The `PropertyReference` and `AuditPropertyReference` conversions
    move with it.
  - New: `ReadAccessResult::encode` in `bacnet_services::rpm`, which the
    ReadPropertyMultiple-ACK encoder now uses. The Python `add_group` builds
    an empty Group and is unchanged.
