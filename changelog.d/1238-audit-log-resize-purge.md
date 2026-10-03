---
section: Added
---
- **Wire:** Audit Log Buffer_Size takes writes while logging is off, keeping the
  newest records that fit, and `BACnetServer::purge_audit_log` (also in Python)
  lets the application purge a log, leaving a BUFFER_PURGED record (#1238).
