---
section: Changed
---
- Test-only: the BACnet/SC redial, failover, primary-restore and connect
  lifecycle tests run on tokio's paused clock, so a stalled runner can no
  longer fire a test's deadline before the transport's own timer (#1549).
