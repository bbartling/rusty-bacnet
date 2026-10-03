---
section: Changed
---
- **Endpoint ReadRange and source Audit READ (Refs #771, #345):** the shared
  endpoint client initiates unsegmented ReadRange through the same prepared
  request, retry, cancellation and source-reporting owners as ReadProperty.
  Each attempted range read emits one value-free record; item bytes stay in the
  correlated caller ACK. Rust request encoding is now fallible and transactional;
  all callers migrate directly. Python standalone/endpoint clients share argument
  validation and the typed `ReadRangeResult` shape (flags tuple and optional first
  sequence), retaining the explicit all-items/position/sequence subset. ByTime is
  Rust-only. Broader Audit families and source RPM/WP remain outside this slice.
