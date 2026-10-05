---
section: Fixed
---
- **Breaking (wire):** an Accumulator serves Scale and Prescale in their
  context-tagged Clause 21 forms instead of application-tagged values, and
  Python reads them back as a float or int and a `(multiplier,
  modulo_divide)` pair, which `add_accumulator` now takes (#1487).
