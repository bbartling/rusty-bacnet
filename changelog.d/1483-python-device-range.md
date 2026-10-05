---
section: Fixed
---
- **Python API:** `who_is`, `discover`, `who_is_directed`, `who_has_by_id`
  and `who_has_by_name` raise `ValueError` for only one of `low_limit` and
  `high_limit`, a low limit above the high one, or a limit past 4194303, where
  one limit used to send a request for every device (#1483).
