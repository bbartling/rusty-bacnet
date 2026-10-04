---
section: Removed
---
- **Breaking (Rust API):** `bacnet_server::handlers::handle_device_communication_control`
  is gone; no server called it, and it stored the DCC state as a raw integer under
  the permissive rules (#1430).
