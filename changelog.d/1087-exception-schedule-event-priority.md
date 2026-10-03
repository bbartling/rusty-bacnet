---
section: Fixed
---
- **Breaking (wire, Rust API):** a special event priority outside 1 to 16 now
  gets VALUE_OUT_OF_RANGE instead of INVALID_DATA_ENCODING, and
  `BACnetSpecialEvent::event_priority` is a `u64` (#1087).
