---
section: Changed
---
- **Rust and Python API:** AddListElement and RemoveListElement request
  encoding returns `Result` and refuses index zero, empty elements and
  malformed framing (#798).
