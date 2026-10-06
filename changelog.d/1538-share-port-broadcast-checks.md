---
section: Added
---
- **Rust and Python API:** a device sharing its port by address fails to start
  unless its broadcast address is its subnet broadcast or 255.255.255.255, and
  keeps only the broadcasts that arrived on its own interface (#1538).
