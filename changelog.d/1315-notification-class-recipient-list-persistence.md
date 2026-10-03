---
section: Added
---
- **Breaking (Rust API):** A Notification Class can keep a written Recipient_List across a
  restart: `NotificationClass::with_persistence` with `FileNotificationClassPersistence`, or
  `storage_path` on Python's `add_notification_class`. `NotificationClass` is no longer
  `UnwindSafe` (#1315).
