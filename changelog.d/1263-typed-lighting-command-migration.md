---
section: Migration notes
---
- **Lighting Output Lighting_Command (#1263):** a read returns
  `PropertyValue::ApplicationData` (Python `application_data`) holding the encoded
  command, and a write takes that encoding instead of an octet string. Build it with
  `bacnet_encoding::constructed::encode_lighting_command`, or set it with
  `LightingOutputObject::set_lighting_command`. A new object reads operation NONE,
  which can't be written back.
