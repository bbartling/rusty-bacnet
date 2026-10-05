---
section: Migration notes
---
- **Color objects (Rust API, #1474):** call
  `ColorObject::set_present_value(BACnetXyColor::new(x, y))`, and handle the
  `Result` it and `ColorTemperatureObject`'s `set_present_value` and
  `set_min_max` return: a value outside the object's range is refused.
