---
section: Added
---
- Trend Log, Trend Log Multiple and Event Log objects restore their records
  and Total_Record_Count before start-up with a validated
  `restore_log_buffer`, which can also seed the count alone, and mark the
  restart with a LOG_INTERRUPTED record from `record_interruption` (#1537).
