---
section: Added
---
- **Breaking (Rust API):** Python servers take a `cov_policy` dict, and the
  new `CovPolicy::validate` refuses zero caps or budgets and unreachable
  reserved peers, so a Rust server configured with them no longer starts
  (#1100).
