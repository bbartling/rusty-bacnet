---
section: Changed
---
- **Breaking (Rust API):** `TimeSyncSourceRestriction` refuses an entry longer
  than 18 octets, which could never match a source; it accepted up to 255
  (#1266).
