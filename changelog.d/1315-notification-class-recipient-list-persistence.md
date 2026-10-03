---
section: Added
---
- A Notification Class can keep a written Recipient_List across a restart:
  `NotificationClass::with_persistence` with `FileNotificationClassPersistence`,
  or `storage_path` on Python's `add_notification_class` (#1315).
