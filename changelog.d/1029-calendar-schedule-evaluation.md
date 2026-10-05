---
section: Fixed
commit: 5dc2537d6cd70588f76f74e85bfd459c94cf1f55
---
- **Breaking (wire, Rust API):** Calendar's Present_Value follows the device's
  local date, and a Schedule evaluates in Clause 12.24.4 order within its
  Effective_Period, writing typed values at Priority_For_Writing to each
  target's array index (#1029, #1028, #845).
