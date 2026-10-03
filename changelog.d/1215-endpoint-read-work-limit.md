---
section: Added
---
- `SessionConfig::read_work_limit` and the endpoint builders' `read_work_limit`
  set the shared endpoint's ReadProperty work limit, which a Group's
  Present_Value read is charged to (default 256) (#1215).
