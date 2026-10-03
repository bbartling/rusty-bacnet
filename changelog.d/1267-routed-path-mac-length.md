---
section: Changed
---
- **Breaking (Rust API):** routed confirmed requests and the routed-path limit
  methods refuse a router MAC, local source MAC or DADR longer than 18 octets
  before the path is reserved, instead of failing later (#1267).
