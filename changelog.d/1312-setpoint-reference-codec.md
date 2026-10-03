---
section: Changed
---
- **Breaking (Rust API):** the Loop and Pulse Converter references read as
  `PropertyValue::ApplicationData`, and `decode_setpoint_reference` takes an empty value
  as no reference and refuses an empty frame (#1312).
