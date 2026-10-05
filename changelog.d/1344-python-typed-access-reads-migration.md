---
section: Migration notes
---
- **Python typed access reads (#1344):** compare reads of the Access Rights
  rule arrays with `AccessRule` mappings carrying every key, and of
  Accompaniment and the zone and user lists with `ObjectIdentifier` or
  `(device, object)` values, not octets; writing a read value back is
  unchanged.
