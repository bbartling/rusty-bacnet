---
section: Changed
---
- **Rust API:** The mutation authorizer decides each Channel write of an
  inbound WriteGroup; `DenyAll` denies them, and the decisions are counted
  (#1319).
