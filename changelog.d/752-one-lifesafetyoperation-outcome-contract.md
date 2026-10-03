---
section: Changed
---
- **Breaking (Rust API):** `BACnetObject::apply_life_safety_operation` returns
  a `LifeSafetyOperationOutcome` listing the exact property changes, replacing
  the `_detailed` hook (#752).
