---
section: Changed
---
- **Breaking (Rust API):** `GroupObject::add_member` returns a `GroupMemberRefusal`
  naming the rule a member breaks, and refuses property identifiers above 4194303 (#1250).
