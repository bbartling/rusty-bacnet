---
section: Fixed
---
- **Rust and Python API:** endpoint clients send ReadPropertyMultiple through
  the shared read path, with ordered ACK correlation and one source READ
  record per reference; RPM request encoding returns `Result` (#780).
