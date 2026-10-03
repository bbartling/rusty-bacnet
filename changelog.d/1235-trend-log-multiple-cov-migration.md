---
section: Migration notes
---
- **Trend Log Multiple (Rust API, #1235):** `set_logging_type` takes a
  `LoggingType` and returns `Result`; handle the VALUE_OUT_OF_RANGE a COV
  value now gets. `TrendLogObject::set_logging_type` takes a `LoggingType`
  too. Object wrappers forward the new
  `BACnetObject::refresh_log_window_internal` hook.
