---
section: Added
---
- **Wire:** Target Audit reporting records each Channel write of an inbound
  WriteGroup as a WRITE of its Present_Value from the requester. A Channel's
  Present_Value counts as commandable, so its WriteProperty records carry the
  priority and drop at priorities Audit_Priority_Filter disables (#1318).
