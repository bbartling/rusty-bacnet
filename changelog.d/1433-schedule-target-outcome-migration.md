---
section: Migration notes
---
- **Schedule target outcomes (Rust API, #1433):** `ScheduleTargetOutcome` has
  a `ReferenceRefused` variant for UNKNOWN_OBJECT, UNKNOWN_PROPERTY,
  PROPERTY_IS_NOT_AN_ARRAY and INVALID_ARRAY_INDEX, which `of` used to map to
  `Failed`. Add an arm to exhaustive matches; a custom Schedule's
  `complete_schedule_write` should treat it as a configuration fault. The
  server reports a missing target object as `ReferenceRefused` directly, not
  through `of`.
