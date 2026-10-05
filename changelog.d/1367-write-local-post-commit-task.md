---
section: Fixed
---
- **Breaking (Rust API):** once `write_local` (or another local write) has
  committed, the COV, event, Schedule and Staging work it owes, and the runs it started, finish in a
  request task, so a dropped or cancelled caller no longer skips them; `stop()` aborts that task (#1367).
