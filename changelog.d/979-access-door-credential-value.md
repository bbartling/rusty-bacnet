---
section: Changed
---
- **Breaking Access Door and Access Credential value checks (Rust API and wire
  behaviour):** the Access Door stores Present_Value, its Priority_Array slots
  and Relinquish_Default as `DoorValue`, and
  `AccessDoorObject::set_relinquish_default` takes a `DoorValue` instead of a
  `u32` (#979). BACnetDoorValue has exactly four values, so a Present_Value
  command outside LOCK (0) to EXTENDED_PULSE_UNLOCK (3) now fails with
  VALUE_OUT_OF_RANGE and leaves the priority array as it was; before, any
  Enumerated was stored. Relinquish_Default already refused such values, and
  the setter still does, including a `DoorValue::from_raw` outside the four.
  The Access Credential stores Credential_Status, a BACnetBinaryPV, as a
  `BinaryPV`, and a write other than INACTIVE (0) or ACTIVE (1) now fails with
  VALUE_OUT_OF_RANGE and leaves the status as it was; before, any Enumerated
  was stored. Values in range read back on the wire exactly as before, and
  `ResolvedEnum::from_property` now names a Credential_Status value as a
  `BinaryPV`. The Python API is unchanged.
