---
section: Migration notes
---
- **Python integer range errors (#1360):** any integer argument outside the
  type of the field it fills raises `OverflowError`, as a parameter, a tuple
  member or a mapping value; catch it where you caught `ValueError` or
  `BacnetProtocolError` for, say, `BACnetTimeStamp.sequence_number(65536)`, a
  Destination `process_identifier` past 2**32 - 1, a channel number past
  65535 or a mapping's negative array index. Values that fit but BACnet
  refuses still raise `ValueError` or `BacnetProtocolError`.
