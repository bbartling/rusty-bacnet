---
section: Fixed
---
- **Wire:** Loop, Schedule and both Trend Log object types compute
  Status_Flags from their state instead of always reading all FALSE, and a
  Loop's flag changes reach COV subscribers (#978).
