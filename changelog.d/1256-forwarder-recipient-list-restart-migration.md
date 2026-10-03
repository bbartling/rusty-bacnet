---
section: Migration notes
---
- **Notification Forwarder persistence (Rust API, #1256):** `SubscribedRecipientsPersistence` and
  `FileSubscribedRecipientsPersistence` are now `NotificationForwarderPersistence` and
  `FileNotificationForwarderPersistence`; `load` returns and `save` takes a `ForwarderSnapshot` with
  both lists (`recipient_list` is `None` until a write sets it). The file backend does not read files
  the old one wrote: delete them.
