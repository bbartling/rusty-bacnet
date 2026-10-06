---
section: Added
---
- **Python API:** `BipTransport::check_bind` binds and releases the sockets
  `start()` would; `BipEndpoint.start()` checks with it first, so endpoints on
  different addresses can share a port (#1538).
