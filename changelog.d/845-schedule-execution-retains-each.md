---
section: Fixed
---
- **Breaking (Rust API):** Schedule execution keeps each target's array index,
  and `BACnetObject::tick_schedule` returns
  `Vec<BACnetObjectPropertyReference>` (#845).
