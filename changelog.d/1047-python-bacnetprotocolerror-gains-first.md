---
section: Fixed
commit: 0f43456afa2ae49d066aa2875d2db1524e0e4966
---
- **Python API:** `BacnetProtocolError` gains the structured error fields
  `first_failed_write_attempt`, `first_failed_subscription`, `vendor_id`,
  `service_number`, `error_parameters` and `vt_session_identifiers` (#1047).
