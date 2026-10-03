---
section: Migration notes
---
- 0.11.0 Audit Log snapshots are converted automatically on first load and saved as schema v3.
  The Python `log_status` int keeps 1 = log-disabled, 2 = buffer-purged, 4 = log-interrupted
  (#1233).
