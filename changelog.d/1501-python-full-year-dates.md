---
section: Changed
---
- **Breaking (Python API):** a `PropertyValue` date reads with the full year
  (2026, not 126) and an unspecified year as 255, as timestamps and schedules
  already did; `PropertyValue.date` and `time_synchronization` refuse other
  years instead of misreading 255 as 1900 (#1501).
