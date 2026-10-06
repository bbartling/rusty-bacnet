---
section: Added
---
- **Rust API:** `BipTransport::check_bind` binds and releases the sockets
  `start()` would. A Python `BipEndpoint` sharing its port by address checks
  with it before starting (#1538).
