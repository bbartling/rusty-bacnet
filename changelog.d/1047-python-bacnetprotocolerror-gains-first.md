---
section: Fixed
---
- **Python API:** `BacnetProtocolError` gains the structured error fields
  `first_failed_write_attempt`, `first_failed_subscription`, `vendor_id`,
  `service_number`, `error_parameters` and `vt_session_identifiers` (#1047).
