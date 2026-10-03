---
section: Migration notes
---
- **Notification Class (Rust API, #1315):** `NotificationClass` is no longer `UnwindSafe` or
  `RefUnwindSafe`, as the Notification Forwarder became with #1270, because it can own a save
  writer. Wrap it in `std::panic::AssertUnwindSafe` to carry it across `catch_unwind`.
