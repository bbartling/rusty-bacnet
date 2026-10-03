---
section: Migration notes
---
- **Global Group (Rust API, #1107):** `GlobalGroupObject::present_value` is a
  `Vec<AccessResult>` holding, by member position, the value or error each
  member's read produced.
