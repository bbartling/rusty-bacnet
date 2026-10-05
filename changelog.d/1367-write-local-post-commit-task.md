---
section: Fixed
---
- **Breaking (Rust API):** once `write_local` (and the other local writes, Python's included) has
  committed, the COV, event, Schedule and Staging work it owes, and the runs it started, finish in a
  request task, so a dropped or cancelled caller no longer skips them; `stop()` aborts that task (#1367).
