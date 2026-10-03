---
section: Migration notes
---
- Audit Log files saved before this release hold log-status records in the old bit order, so a
  stored log-disabled record reads back as log-interrupted; purge or rewrite those logs. The
  Python `log_status` int keeps 1 = log-disabled, 2 = buffer-purged, 4 = log-interrupted (#1233).
