---
section: Changed
---
- Default configured-server DCC authorization to deny all, even with a correct
  configured password. Add explicit Rust `DccPolicy` and Python keyword-only
  `dcc_policy` modes; deprecated DISABLE remains denied in every mode.
