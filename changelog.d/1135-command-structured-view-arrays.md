---
section: Fixed
---
- **Breaking Structured View and Command arrays (wire and Rust API):** an
  indexed read of Subordinate_List, Subordinate_Annotations or Action now
  returns one element, and Subordinate_List and Action elements go out in
  their Clause 21 forms (#1135).
  - Index 0 reads the array size, indexes 1 to N one element, and a larger
    index fails with PROPERTY / INVALID_ARRAY_INDEX, through ReadProperty and
    ReadPropertyMultiple. All three returned the whole array for any index.
    An element read alone carries the same octets the whole-array read
    concatenates.
  - A Subordinate_List element is a BACnetDeviceObjectReference: the object
    under `[1]`, after the device under `[0]` for a subordinate in another
    device. It used to go out as a bare application-tagged object identifier.
    `StructuredViewObject::subordinate_list` is now a
    `Vec<BACnetDeviceObjectReference>`, and `add_subordinate` takes anything
    that converts into one, so an `ObjectIdentifier` still adds a local
    subordinate.
  - An Action element is a BACnetActionList: its BACnetActionCommand writes
    back to back inside `[0]`. It used to go out as an application-tagged
    Octet String of opaque bytes. `CommandObject::set_action` now takes
    `Vec<BACnetActionList>` and returns `Result`, refusing with PROPERTY /
    VALUE_OUT_OF_RANGE a command whose priority is outside 1 to 16 or whose
    value has no encoding.
  - All three stay read-only: a write, whole or indexed, fails with PROPERTY
    / WRITE_ACCESS_DENIED as before.
  - New: `BACnetActionCommand`, `BACnetActionList` and
    `From<ObjectIdentifier> for BACnetDeviceObjectReference` in
    `bacnet_types::constructed`, and `encode_action_command`,
    `decode_action_command`, `encode_action_list` and `decode_action_list` in
    `bacnet_encoding::constructed`. The Python `add_command` and
    `add_structured_view` build empty objects and are unchanged.
