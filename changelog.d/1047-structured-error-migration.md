---
section: Migration notes
commit: 0f43456afa2ae49d066aa2875d2db1524e0e4966
---
- **Structured errors (Rust API, #1047, #1048):** `Error` gains
  `Structured { class, code, detail }`, and `TsmResponse::Error` gains
  `detail`. Some list-write refusals now return `Error::Structured` where they
  returned `Error::Protocol`, so match both for the class and code.
