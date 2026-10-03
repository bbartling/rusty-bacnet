---
section: Changed
---
- **Breaking (Rust API):** `EventLogDatum::Notification` holds a typed
  `EventNotificationRequest` instead of encoded bytes. The request, its event
  values and `BACnetPropertyValue` move to bacnet-types, with their codecs in
  bacnet-encoding (#1276).
