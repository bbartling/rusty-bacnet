---
section: Changed
---
- **Breaking (Rust API):** Notification Class recipients use typed bit strings
  (`DaysOfWeek`, `EventTransitionBits`), and `pack_octet` and `unpack_octet`
  are no longer public (#930).
