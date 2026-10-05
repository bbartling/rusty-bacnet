---
section: Migration notes
---
- **Dates (Python API, #1501):** a `"date"` value's `.value` gives the full
  year, so drop any `+ 1900` applied to it; an unspecified year still reads
  as 255, `rusty_bacnet.UNSPECIFIED`. `PropertyValue.date` takes 1900 to 2154
  or 255. `time_synchronization` and `utc_time_synchronization` need a real
  date with its own weekday and a time with no field unspecified.
