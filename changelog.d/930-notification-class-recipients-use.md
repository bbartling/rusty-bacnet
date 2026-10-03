---
section: Changed
commit: e67cd5cbd2c3dded0df9b19edf9de241e6d192c4
---
- **Breaking (Rust API):** Notification Class recipients use typed bit strings
  (`DaysOfWeek`, `EventTransitionBits`), and `pack_octet` and `unpack_octet`
  are no longer public (#930).
