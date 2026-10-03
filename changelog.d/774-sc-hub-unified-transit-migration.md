---
section: Migration notes
---
- **SC hub relay budget (#774):** use `with_relay_send_budget`,
  `relay_send_budget` and `validate_relay_send_budget` in Rust, and
  `relay_send_budget_ms` in Python, in place of the unicast-only setting;
  there are no aliases.
