---
section: Migration notes
---
- **Trend Log (Rust API, #1354):** `TrendLogObject::set_logging_type`
  returns `Result`; handle the OPTIONAL_FUNCTIONALITY_NOT_SUPPORTED a COV
  value gets until COV acquisition lands (#1480). To stop a polled Trend Log,
  clear Enable or make it TRIGGERED: writing its Log_Interval from nonzero to
  zero is refused the same way.
