---
section: Migration notes
---
- **Access control (Rust API, #1284, #1285):**
  `AccessPointObject::set_access_event` takes a fourth argument, the
  credential (`None` for none), and returns `Result`;
  `AccessDoorObject::set_door_members` and
  `StructuredViewObject::add_subordinate` return `Result`. The Structured
  View subordinate fields are private: replace them with `set_subordinates`
  and read them with `subordinates()`.
