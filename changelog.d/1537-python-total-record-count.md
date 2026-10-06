---
section: Added
---
- **Python API:** `add_trend_log`, `add_trend_log_multiple` and
  `add_event_log` take a keyword-only `total_record_count` that seeds the
  log's count, so its records can be numbered across the Unsigned32 wrap
  (#1537).
