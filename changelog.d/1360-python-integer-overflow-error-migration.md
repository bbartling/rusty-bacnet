---
section: Migration notes
---
- **Python integer range errors (#1360):** catch `OverflowError` for an
  integer outside its field's type: a mapping's array index or priority, a
  channel number past 65535, a credential vendor member past 65535, a
  priority past 255 and the audit configuration integers. `ValueError` and
  `BacnetProtocolError` remain for values that fit but BACnet refuses.
