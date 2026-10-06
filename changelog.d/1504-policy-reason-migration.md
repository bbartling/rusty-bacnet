---
section: Migration notes
---
- **Endpoint ingress (Rust API, #1504):** `PolicyReason` has a new
  `GroupSource` variant; an exhaustive `match` on it needs an arm for it.
