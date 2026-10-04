---
section: Migration notes
---
- **Access Rights (Rust API, #1392):** `AccessRightsObject` is no longer `UnwindSafe` or
  `RefUnwindSafe`, as `NotificationClass` became with #1315, because it can own a save writer.
  Wrap it in `std::panic::AssertUnwindSafe` to carry it across `catch_unwind`.
