---
section: Fixed
---
- **Wire:** Lighting Output stores a Present_Value or Relinquish_Default level
  above 0.0 and below 1.0 as 1.0, and -0.0 as 0.0. Tracking_Value, which
  always read 0.0, now follows Present_Value on every write (#1385).
