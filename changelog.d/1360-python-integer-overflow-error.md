---
section: Changed
---
- **Breaking (Python API):** an integer argument outside the type of the field
  it fills raises `OverflowError` everywhere, as a mapping value or tuple
  member as well as a parameter, instead of `ValueError` or
  `BacnetProtocolError` on some paths (#1360).
