---
section: Migration notes
---
- **Multi-state objects (Rust API, #1443):** Number_Of_States rows carry the
  new `PropertyWriteCapability::Through(STATE_TEXT)`, which doesn't count as
  writable; the PICS row carries `PropertySupport::written_through`.
