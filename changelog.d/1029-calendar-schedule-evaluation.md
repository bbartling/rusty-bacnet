---
section: Fixed
---
- **Breaking (wire, Rust API):** Calendar's Present_Value follows the device's
  local date, and a Schedule evaluates in Clause 12.24.4 order within its
  Effective_Period, writing typed values at Priority_For_Writing (#1029,
  #1028).
