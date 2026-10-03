---
section: Migration notes
---
- `EventLogObject` stores `BACnetEventLogRecord` (log status, notification parameters or time
  change); `LogDatum::SignedValue` is `i32`. Read a log's records through `records()` or
  ReadRange, not ReadProperty; object wrappers forward the new
  `BACnetObject::log_buffer_internal` hook (#1233, #1237).
