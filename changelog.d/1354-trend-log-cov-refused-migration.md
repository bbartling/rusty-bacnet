---
section: Migration notes
---
- **Trend Log (Rust API, #1354):** `TrendLogObject::set_logging_type`
  returns `Result`; handle the VALUE_OUT_OF_RANGE a COV value now gets. To
  stop a polled Trend Log, clear Enable or make it TRIGGERED: writing its
  Log_Interval from nonzero to zero is refused.
