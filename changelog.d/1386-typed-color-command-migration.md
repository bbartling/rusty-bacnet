---
section: Migration notes
---
- **Color and Color Temperature Color_Command (#1386):** a read returns
  `PropertyValue::ApplicationData` holding the encoded command, and a write takes
  that encoding instead of an octet string. Build it with
  `bacnet_encoding::constructed::encode_color_command`, or set it with
  `set_color_command` on `ColorObject` or `ColorTemperatureObject`. A new object
  reads operation NONE, which can't be written back.
