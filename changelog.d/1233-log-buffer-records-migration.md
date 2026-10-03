---
section: Migration notes
---
- `EventLogObject` stores `BACnetEventLogRecord`; log statuses are `LogStatus`, Trend Log
  `status_flags` is `Option<StatusFlags>`, and INTEGER/ENUMERATED log values are `i64`/`u64`.
  Read records through `records()` or ReadRange; wrappers forward `log_buffer_internal`, whose
  `encode_record` returns nothing (#1233, #1237).
