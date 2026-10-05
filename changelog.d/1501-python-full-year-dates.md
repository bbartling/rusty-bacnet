---
section: Changed
---
- **Breaking (Python API):** a `PropertyValue` date reads with the full year
  (2026, not 126) and an unspecified year as 255 (`UNSPECIFIED`); and
  `time_synchronization` and `utc_time_synchronization` take only a
  specific date and time, raising `ValueError` otherwise (#1501).
