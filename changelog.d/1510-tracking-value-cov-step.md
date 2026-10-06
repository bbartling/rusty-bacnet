---
section: Changed
---
- **Wire:** While a Lighting Output or Color Temperature fade or ramp runs, a
  Tracking_Value subscriber whose COV increment is finer than the object's
  sample step now hears each of its own steps, at most one per 100 ms
  (#1510).
