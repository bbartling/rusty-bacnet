---
section: Changed
---
- Reading a Group's Present_Value charges every member row to the request's
  ReadPropertyMultiple work limit, so a request that would pass it is aborted
  with OUT_OF_RESOURCES (#1172).
