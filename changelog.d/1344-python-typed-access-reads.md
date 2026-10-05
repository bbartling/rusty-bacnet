---
section: Changed
---
- **Breaking (Python API):** Access Zone Entry_Points and Exit_Points and
  Access User Credentials read as `device_object_reference` values, an
  `ObjectIdentifier` or a `(device, object)` pair, where a 0.11.0 local read
  gave plain object identifiers (#1344).
