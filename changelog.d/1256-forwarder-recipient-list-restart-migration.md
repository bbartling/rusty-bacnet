---
section: Migration notes
---
- **Notification Forwarder persistence (Rust API, #1256):** `SubscribedRecipientsPersistence` and
  `FileSubscribedRecipientsPersistence` are now `NotificationForwarderPersistence` and
  `FileNotificationForwarderPersistence`, taking a `ForwarderSnapshot` of both lists; delete files
  the old backend wrote. Custom forwarder and Audit Log persistence runs on a plain `std` thread
  with no Tokio context, and a panic there fails the save (#1270).
