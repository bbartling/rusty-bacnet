---
section: Changed
---
- **Breaking DCC source restriction entry length:** `DccSourceRestriction`
  and the Python `dcc_source_restriction` keyword refuse an entry longer than
  `BACnetAddress::MAX_MAC_LEN` (18 octets), which could never match a source;
  they accepted up to 255 (#1157).
