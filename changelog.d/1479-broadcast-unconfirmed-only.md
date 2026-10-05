---
section: Changed
---
- **Breaking (Rust API):** `NetworkLayer` broadcasts only an
  Unconfirmed-Request, naming any other PDU type it refuses, as does a routed
  send with no DADR; `BACnetClient` refuses a confirmed request to the link's
  broadcast MAC, and `send_apdu_routed_via_local_broadcast` an empty DADR
  (#1479).
