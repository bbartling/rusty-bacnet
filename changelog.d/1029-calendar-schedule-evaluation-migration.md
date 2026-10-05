---
section: Migration notes
commit: 5dc2537d6cd70588f76f74e85bfd459c94cf1f55
---
- **Calendar and Schedule (Rust API, #1029, #845):** Calendar's
  `set_present_value` is gone and `add_date_entry` returns `Result`.
  `BACnetTimeValue::value` is a primitive `PropertyValue`. `tick_schedule`
  takes the date, the time and a Calendar resolver, not the weekday, hour and
  minute, and returns `Option<ScheduleWrite>`, whose `references` keep their
  array index, not a value with `(ObjectIdentifier, u32)` pairs. The Schedule
  setters and the `bacnet-encoding` schedule encoders return `Result`.
