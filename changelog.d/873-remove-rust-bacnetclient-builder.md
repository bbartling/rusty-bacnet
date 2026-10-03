---
section: Changed
---
- Remove the pre-1.0 Rust `BACnetClient::builder()` and
  `BACnetServer::builder()` aliases. Rust callers must use `bip_builder()` for
  B/IP; builder options/defaults, SC/generic builders and Python constructors
  are unchanged (#873).
