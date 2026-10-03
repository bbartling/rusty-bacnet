---
section: Migration notes
---
- `GroupObject::add_member` errors are `GroupMemberRefusal`; use `?` or
  `Error::from` where a `bacnet_types::error::Error` is needed (#1250).
