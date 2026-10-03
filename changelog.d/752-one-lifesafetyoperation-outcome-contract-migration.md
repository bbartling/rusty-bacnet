---
section: Migration notes
---
- **LifeSafetyOperation (Rust API, #752):** custom objects return
  `LifeSafetyOperationOutcome` from `apply_life_safety_operation`, listing the
  properties they changed for COV, and drop the `_detailed` hook.
