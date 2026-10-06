---
section: Added
---
- **Python API:** `read_log_page` pages a log by cursor, `decode_log_records`
  types records, `read_range(validation="lenient")` keeps a page that breaks a
  rule (strict raises `BacnetReadRangeViolationError`), and
  `BACnetClient(min_request_interval_ms=...)` paces requests (#1530, #1534,
  #1531, #1535).
