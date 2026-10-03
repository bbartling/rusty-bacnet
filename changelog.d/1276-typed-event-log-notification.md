---
section: Changed
---
- **Breaking (Rust API):** `EventLogDatum::Notification` holds a typed
  `EventNotificationRequest`, now in bacnet-types with its codec in
  bacnet-encoding. `decode_event_log_record` refuses a notification that isn't
  a valid request, but drops an unreadable message text (#1276).
