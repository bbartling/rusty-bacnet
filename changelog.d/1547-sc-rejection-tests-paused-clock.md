---
section: Changed
---
- Test-only: the BACnet/SC rejection-deadline and recovery tests run on
  tokio's paused clock, so a stalled runner can no longer fire a NAK budget
  and a test's own deadline in the same turn (#1547).
