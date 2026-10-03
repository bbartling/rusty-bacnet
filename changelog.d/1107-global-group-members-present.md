---
section: Fixed
---
- **Breaking wire behaviour and Rust API:** the Global Group's Group_Members
  and Present_Value now go out in their Clause 21 forms, and an indexed read
  of its arrays returns one element (#1107).
  - Group_Members is an array of BACnetDeviceObjectPropertyReference: each
    member's object `[0]` and property `[1]`, then its array index `[2]` and
    device `[3]` when it has them. It used to go out as application-tagged
    values with a NULL standing in for a missing index or device.
  - Present_Value is an array of BACnetPropertyAccessResult with one element
    per member: the member's reference, then the value read inside `[4]` or
    the error class and code inside `[5]`. It used to carry the stored values
    bare, with no reference and no way to report a member that couldn't be
    read. `GlobalGroupObject::present_value` is now a `Vec<AccessResult>`
    where the application stores, by member position, the value or the error
    each member's read produced. A member with no stored result reads
    PROPERTY / VALUE_NOT_INITIALIZED, the result Clause 12.50.7.1 gives a new
    element, and results past the last member are not served.
  - Index 0 of Group_Members, Present_Value and Group_Member_Names reads the
    array size, indexes 1 to N one element, and a larger index fails with
    PROPERTY / INVALID_ARRAY_INDEX. All three returned the whole array for
    any index.
  - Member_Status_Flags still combines the bit-string values of the members
    that reference Status_Flags; an error result adds nothing.
  - New: `AccessResult` and `BACnetPropertyAccessResult` in
    `bacnet_types::constructed`, and `encode_property_access_result`,
    `decode_property_access_result` and
    `encode_device_object_property_reference` in
    `bacnet_encoding::constructed`. The Python `add_global_group` builds an
    empty group and is unchanged.
