---
section: Fixed
---
- **Breaking (Python API):** `BACnetServer.read_property` reads through the
  server's ReadProperty evaluator, so a Group's Present_Value and other derived
  values match a network read, and an unknown object raises `BacnetProtocolError`
  (#1297).
