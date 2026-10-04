---
section: Migration notes
---
- **Device reference setters (Rust API, #1308):**
  `EventEnrollmentObject::set_object_property_reference` returns `Result`;
  `GlobalGroupObject::group_members` is private, so set it with
  `set_group_members` or `add_group_member` (both `Result`) and read it with
  `group_members()`.
