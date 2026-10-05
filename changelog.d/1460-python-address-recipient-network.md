---
section: Changed
---
- **Python API:** `configure_audit_recipient` accepts an Address on a network numbered 1 to 65534,
  not only network 0, so a server can report to a logger named by its own network's number
  (#1460).
