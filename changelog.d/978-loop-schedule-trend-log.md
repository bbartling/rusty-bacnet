---
section: Fixed
commit: d5f0be714354749fd13483501e553bbdd8c2498e
---
- **Wire:** Loop, Schedule and both Trend Log object types compute
  Status_Flags from their state instead of always reading all FALSE, and a
  Loop's flag changes reach COV subscribers (#978).
