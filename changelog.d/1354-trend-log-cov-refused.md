---
section: Changed
---
- **Breaking (wire, Rust API):** Trend Log refuses COV logging, which the
  stack can't do yet, whether asked through Logging_Type or by writing a
  polled log's Log_Interval to zero; `TrendLogObject::set_logging_type`
  returns `Result` (#1354).
