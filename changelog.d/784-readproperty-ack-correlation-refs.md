---
section: Changed
---
- **ReadProperty ACK correlation (Refs #784, #345):** standalone direct/routed
  and endpoint clients share object/property/array-index validation. Device and
  Network Port wildcard requests accept only a same-type concrete peer-reported
  object. Successful source Audit records use that validated object; concrete
  Device ACKs also establish Target Device for that record without a cache.
  Failed attempts retain the requested identity and target address without
  trusting malformed ACK data.
  Rust/Python return shapes stay unchanged; mismatched ACKs are decoding errors.
  Network Port alias resolution in the bundled server remains separate (#785).
