---
section: Changed
---
- **Breaking (Rust API):** `ColorObject::set_present_value` takes a
  `BACnetXyColor`, and the colour objects' `set_present_value` and
  `set_min_max` check their values and return `Result` (#1474).
