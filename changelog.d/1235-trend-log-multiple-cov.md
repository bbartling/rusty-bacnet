---
section: Changed
---
- **Breaking (wire, Rust API):** Trend Log Multiple refuses COV logging, over
  the wire and through `set_logging_type`, which returns `Result`; both trend
  objects' `set_logging_type` take a `LoggingType`, and a log with a
  proprietary Logging_Type is no longer polled (#1235).
