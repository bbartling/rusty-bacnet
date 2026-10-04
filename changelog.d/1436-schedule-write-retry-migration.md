---
section: Migration notes
---
- **Schedule writes (Rust API, #1436):** `ScheduleWrite` has a `retry` field:
  set it to `false` in struct literals, and name it or add `..` in patterns
  that destructure the struct. A custom Schedule's `tick_schedule` may return
  its current value for the references that refused it, with `retry: true`,
  when nothing else is owed; a retry that fails otherwise should end that
  member's refusal.
