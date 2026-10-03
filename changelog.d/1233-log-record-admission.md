---
section: Fixed
---
- **Breaking:** Log objects refuse a record that would not encode when it is added, and the
  pollers log an any-value over 256 octets as PROPERTY / VALUE_TOO_LONG, so every stored record
  can be served (#1233, #1236).
