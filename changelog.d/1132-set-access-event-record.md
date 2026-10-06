---
section: Changed
---
- **Breaking (Rust API):** `AccessPointObject::set_access_event` takes an
  `AccessEventReport`, which adds the authentication factor and lets the time
  default to the Device clock's, and `BACnetObject` gains
  `report_access_input_internal` (#1132).
