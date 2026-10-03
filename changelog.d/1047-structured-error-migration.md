---
section: Migration notes
---
- **Structured errors (Rust API, #1047, #1048):** `Error::ChangeList` is
  replaced by `Error::Structured { class, code, detail }`, and
  `TsmResponse::Error` gains `detail`. Some list-write refusals now return
  `Error::Structured` where they returned `Error::Protocol`, so match both for
  the class and code.
