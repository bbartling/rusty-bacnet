---
section: Fixed
---
- **Breaking Elevator Group landing calls (API and wire format):** the
  Elevator Group object's Landing_Call_Control and Landing_Calls now carry
  BACnetLandingCallStatus values, as Clause 12.58 (Table 12-76) and Clause 21
  define them (#980). On the wire, Landing_Call_Control changes from an
  Enumerated to that constructed value and Landing_Calls from an Unsigned
  count, which was always 0, to a BACnetLIST of them. In the Rust API, the
  public `bacnet_types::constructed::BACnetAssignedLandingCalls`, shipped
  since 0.10.0 but unused and matching neither production, is removed. A call
  is a floor number, then either a direction (BACnetLiftCarDirection) or a
  destination floor, and an optional floor label. `bacnet-types` adds
  `constructed::{BACnetLandingCallStatus, LandingCallCommand}` and
  `bacnet-encoding` adds `encode_landing_call_status`,
  `decode_landing_call_status` and their `_list` forms. Landing_Call_Control
  stays writable and now validates writes, separating a malformed encoding
  from an out-of-range value as Clause 15.9.1.3 does: a value that isn't this
  type is refused with INVALID_DATA_TYPE, bytes that don't decode as exactly
  one call with INVALID_DATA_ENCODING, and a well-formed call whose floor
  number or destination exceeds 255, or whose direction is reserved or above
  65535, with VALUE_OUT_OF_RANGE. Before any write it reads floor 0 with
  direction UNKNOWN. Landing_Calls stays read-only over the network and reads
  as a BACnetLIST that the application sets with
  `ElevatorGroupObject::set_landing_calls`, which refuses a reserved
  direction; `landing_calls()` and `landing_call_control()` read them back. A
  Landing_Call_Control write doesn't add to the list.
