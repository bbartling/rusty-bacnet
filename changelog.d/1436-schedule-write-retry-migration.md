---
section: Migration notes
---
- **Schedule writes (Rust API, #1436):** `ScheduleWrite` has a `retry` field;
  set it to `false` in struct literals. A custom Schedule's `tick_schedule`
  may return its current value for the references that refused it, with
  `retry: true`, when nothing else is owed; the server logs failures of such
  a write at debug.
