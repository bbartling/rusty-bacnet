---
section: Fixed
---
- **Breaking (Rust API):** COV compares a typed sample with validated
  Status_Flags, so a status-only change passes the threshold and a late
  unconfirmed send can't replace a newer one; `last_notified_observation`
  replaces `last_notified_value` and its setter (#810, #817, #826, #833,
  #840).
