---
section: Fixed
---
- **Breaking (wire, Rust API):** service decoders refuse octets after a
  request's last member, so the server answers such a file, DeleteObject, DCC,
  ReinitializeDevice or GetAlarmSummary request with SERVICES / OTHER and drops
  such a Who-Is, Who-Has or I-Am instead of serving it (#1411).
