---
section: Migration notes
---
- **Structured View and Command (Rust API, #1135):**
  `StructuredViewObject::subordinate_list` holds `BACnetDeviceObjectReference`
  values (an `ObjectIdentifier` still converts), and
  `CommandObject::set_action` takes `Vec<BACnetActionList>` and returns
  `Result`.
