---
section: Fixed
---
- **Rust API:** the typed ValueSource codec prerequisite for #824:
  `BACnetValueSource::Object` carries a `BACnetDeviceObjectReference`, encoded
  by `encode_value_source` and `decode_value_source` (#824).
