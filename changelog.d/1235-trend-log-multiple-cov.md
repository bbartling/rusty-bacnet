---
section: Changed
---
- **Breaking (wire, Rust API):** Trend Log Multiple refuses COV logging,
  through a client's Logging_Type write and through `set_logging_type`,
  which now returns `Result` (#1235).
