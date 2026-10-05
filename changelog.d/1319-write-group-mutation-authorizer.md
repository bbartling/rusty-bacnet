---
section: Changed
---
- **Breaking (Rust API):** The mutation authorizer decides each Channel write
  of an inbound WriteGroup instead of the server dropping every WriteGroup
  while one is installed; `DenyAll` denies them, and the decisions are counted
  (#1319).
