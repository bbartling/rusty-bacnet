---
section: Changed
---
- **SC MU-rejection liveness ordering (Refs #519):** unsupported Must Understand
  Destination Options on received NPDUs no longer refresh node activity or clear
  a pending heartbeat. Existing unicast NAKs, broadcast silence and Data Options
  behavior remain. This is [local admission policy](docs/conformance/standard-135-2020-ledger.md#mu-rejection-liveness-accounting),
  not universal invalid-frame accounting. At that slice, timer progress depended
  on receive loop progress; the rejection-NAK budget supplement above now addresses
  those three original NAK paths, with the fourth empty-NPDU path added above,
  not general write backpressure. #519 stays open.
