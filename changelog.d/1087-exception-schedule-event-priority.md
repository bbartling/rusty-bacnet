---
section: Fixed
---
- **Breaking Exception_Schedule event priority (Rust API and wire):** a
  special event whose priority is outside 1 to 16 now gets VALUE_OUT_OF_RANGE
  from WriteProperty and WritePropertyMultiple, the error `add_exception`
  gives it, instead of INVALID_DATA_ENCODING (#1087). The shared codec
  (`decode_special_event`, `decode_exception_schedule`) now decodes any
  Unsigned priority and leaves the range to the caller, as the calendar-entry
  codec does for its octets; the Schedule object checks it on every path.
  `BACnetSpecialEvent::event_priority` is now a `u64`, so a decoded value
  is kept whole.
