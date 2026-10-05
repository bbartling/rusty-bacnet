---
section: Fixed
---
- **Python API:** `PropertyValue.list` raises `ValueError` past 32 levels of
  nesting, pickles included, instead of crashing the process on a deep list,
  and `PropertyValue.real(0.0)` and `real(-0.0)`, equal already, now hash
  alike, as do `double` zeros (#1506).
