---
section: Fixed
---
- **Averaging references naming this device (wire):** an Averaging object's
  Object_Property_Reference whose Device member is the server's own Device is
  now accepted (#1153). Clause 12.5.13 lets the object sample only its own
  device, which allows refusing a reference into another device but not one
  into this device. The server stores such a reference, through WriteProperty,
  WritePropertyMultiple and `write_local`, as the local reference it stands
  for, and it reads back without the Device member. A reference naming any
  other device is now OPTIONAL_FUNCTIONALITY_NOT_SUPPORTED, the code the other
  device-restricted references use, where it was INVALID_DATA_ENCODING though
  the encoding is valid. An `AveragingObject` written directly still refuses
  every Device member. The other device-restricted reference properties named
  in #1153 needed no change: they are read-only in this stack or not
  implemented yet.
