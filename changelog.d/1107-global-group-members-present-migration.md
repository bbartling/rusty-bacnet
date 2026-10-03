---
section: Migration notes
commit: 0980c10774260915fc65845d99e8fa05b07fee5f
---
- **Global Group (Rust API, #1107):** `GlobalGroupObject::present_value` is a
  `Vec<AccessResult>` holding, by member position, the value or error each
  member's read produced.
