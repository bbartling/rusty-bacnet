---
section: Added
commit: 4535b222d513c705c3080ee57297e3cb3d014aa1
---
- **Rust API:** Python servers take a `cov_policy` dict, and the new
  `CovPolicy::validate` refuses zero caps or budgets and unreachable reserved
  peers, so a Rust server configured with them doesn't start (#1100).
