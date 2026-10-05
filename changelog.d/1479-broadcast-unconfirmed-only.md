---
section: Changed
---
- **Breaking (Rust API):** `NetworkLayer` broadcasts only an
  Unconfirmed-Request, naming any other PDU type it refuses, as does a routed
  send with no DADR; `send_apdu_routed_via_local_broadcast` refuses an empty
  DADR. A confirmed call to a broadcast or group address fails in Rust and
  Python (#1479).
