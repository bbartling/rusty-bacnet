---
section: Migration notes
---
- **Reference setters (Rust API, #1182, #1234):** the Life Safety `add_member`
  and `add_zone_member` take a `BACnetDeviceObjectReference` (an
  `ObjectIdentifier` converts), and they, `set_log_device_object_property` and
  `add_property_reference` return `Result`; handle it. Reads of these
  references are now `PropertyValue::ApplicationData`.
