---
section: Migration notes
---
- **Python typed access reads (#1344):** compare reads of Entry_Points,
  Exit_Points and Credentials with `ObjectIdentifier` or `(device, object)`
  values tagged `device_object_reference`, not 0.11.0's plain object
  identifiers; writing a read value back is unchanged.
