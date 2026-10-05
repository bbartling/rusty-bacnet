---
section: Migration notes
---
- **Python dates (#1501):** a `"date"` value's `.value` gives the full year,
  so drop any `+ 1900` applied to it; an unspecified year still reads as 255.
  `PropertyValue.date`, `time_synchronization` and
  `utc_time_synchronization` take 1900 to 2154 or 255 and raise `ValueError`
  for any other year, so pass 255, not a raw octet, for an unspecified year.
