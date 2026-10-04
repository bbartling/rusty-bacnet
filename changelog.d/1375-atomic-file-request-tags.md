---
section: Fixed
---
- **Breaking (wire, Rust API):** AtomicReadFile and AtomicWriteFile requests
  with a member under any tag but its application tag are refused with
  SERVICES / OTHER instead of being served (#1375).
