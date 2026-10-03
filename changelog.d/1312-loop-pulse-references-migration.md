---
section: Migration notes
---
- **Loop and Pulse Converter references (#1312):** a read now returns
  `PropertyValue::ApplicationData` (Python `application_data`) holding the encoded
  reference, and a write takes that encoding; decode it with
  `bacnet_encoding::constructed::decode_object_property_reference`, or
  `decode_setpoint_reference` for Setpoint_Reference. Clear a reference with Null, or
  Setpoint_Reference with the empty value. Null, an empty [0] frame and unframed members
  no longer write Setpoint_Reference.
