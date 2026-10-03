---
section: Fixed
---
- **Breaking (wire, Rust API):** router rejects go back to whoever first sent
  the refused NPDU, using its SNET/SADR, and a received reject is relayed by
  its DNET/DADR (#1158).
