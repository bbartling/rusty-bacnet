---
section: Added
---
- **Breaking (Rust API):** `read_range_with` and `ReadRangeValidation::Lenient`
  keep a ReadRange page that breaks a rule, listing the rules it broke; a
  strict refusal is now `Error::ReadRangeViolation` naming the rule, and also
  catches contradictory result flags and a count overrun (#1531).
