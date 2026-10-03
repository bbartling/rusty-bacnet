---
section: Fixed
---
- **Wire:** WriteProperty and WritePropertyMultiple can clear a list property
  such as Alarm_Values with an empty value, and the multi-state objects take a
  one-element Alarm_Values: a list property reaches the object as a list at
  every length (#1328).
