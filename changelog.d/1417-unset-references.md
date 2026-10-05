---
section: Changed
---
- **Breaking (wire):** an unset Loop, Pulse Converter, Trend Log, Averaging or
  Event Enrollment reference reads as a reference to instance 4194303, which
  clears one when written, and a NULL written to it, or to Fault_Parameters,
  succeeds and changes nothing (#1417).
