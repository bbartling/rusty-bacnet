---
section: Fixed
---
- **Breaking (Python API):** `BACnetServer.read_property` reads through the
  server's ReadProperty evaluator and `write_property_local` decodes its value
  as a network WriteProperty does, so local reads and writes match network ones
  and what one reads writes back (#1297).
