---
section: Migration notes
---
- **Calendar and Schedule (Rust API, #1029):** the Calendar's
  `set_present_value` is gone and `add_date_entry` returns `Result`.
  `BACnetTimeValue::value` is a primitive `PropertyValue`, `tick_schedule`
  takes the date, the time and a Calendar resolver and returns
  `ScheduleWrite`, and the Schedule setters and the schedule encoders in
  `bacnet-encoding` return `Result`.
