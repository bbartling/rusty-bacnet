---
section: Migration notes
commit: b7f12093227a886113ca8d63eb6f488a65e185cb
---
- **Structured View and Command (Rust API, #1135):**
  `StructuredViewObject::subordinate_list` holds `BACnetDeviceObjectReference`
  values (an `ObjectIdentifier` still converts), and
  `CommandObject::set_action` takes `Vec<BACnetActionList>` and returns
  `Result`.
