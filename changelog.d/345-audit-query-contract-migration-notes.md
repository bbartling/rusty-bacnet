---
section: Migration notes
---
- **Audit queries (#345):** Rust callers pass
  `BACnetSuccessFilter::{ALL, SUCCESSES_ONLY, FAILURES_ONLY}` and
  `Option<u64>` cursors. Python callers pass `successful_actions_only` as 0, 1
  or 2 instead of a bool: 1 for the old `True` and 0 for the old `False`.
