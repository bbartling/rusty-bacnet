---
section: Fixed
---
- **Breaking (wire, Rust API):** the network layer drops and counts an NPDU
  whose DLEN or SLEN exceeds 18 octets, a router rejects one naming a DNET
  with reason 6, and `decode_npdu` returns `NpduDecodeError` (#1141).
