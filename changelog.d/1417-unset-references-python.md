---
section: Changed
---
- **Python API:** reading an unset reference property returns
  `application_data` naming instance 4194303 instead of null, and
  `write_property_local` of null on one leaves it as it is (#1417).
