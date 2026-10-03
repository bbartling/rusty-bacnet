---
section: Fixed
commit: 122b6295263ed98daa8f360d5a3c81a1a8b3bcc5
---
- **Breaking (wire, Rust API):** a special event priority outside 1 to 16 now
  gets VALUE_OUT_OF_RANGE instead of INVALID_DATA_ENCODING, and
  `BACnetSpecialEvent::event_priority` is a `u64` (#1087).
