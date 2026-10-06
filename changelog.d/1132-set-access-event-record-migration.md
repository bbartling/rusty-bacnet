---
section: Migration notes
---
- **Access Point (Rust API, #1132):** replace
  `set_access_event(event, tag, time, credential)` with
  `set_access_event(AccessEventReport { time: Some(time), credential,
  ..AccessEventReport::new(event, tag) })`; the report's
  `authentication_factor` sets Access_Event_Authentication_Factor. A wrapper
  that forwards `BACnetObject` methods forwards `report_access_input_internal`
  too.
