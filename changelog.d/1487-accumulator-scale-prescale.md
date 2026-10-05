---
section: Fixed
---
- **Breaking (wire, Python API, Rust API):** an Accumulator serves Scale and
  Prescale in their context-tagged Clause 21 forms, Python reads them as a
  float or int and a `(multiplier, modulo_divide)` pair that
  `add_accumulator` now takes, and Rust reads them as `ApplicationData`
  (#1487).
