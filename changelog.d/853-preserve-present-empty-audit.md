---
section: Fixed
---
- Preserve present empty Audit Target_Value and Current_Value fields (#853),
  including target Recipient_List writes and list-operation observations.
  Rust `Some(empty)` and Python `b""` remain distinct from absent values and
  encoded NULL; Reporter inclusion retains complete values through 32 octets.
