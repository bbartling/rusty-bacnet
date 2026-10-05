---
section: Migration notes
---
- **Device bindings (Rust and Python API, #1493):** a binding at a multicast
  address, 255.255.255.255 or the broadcast IP at another port, as the
  device's own address or its router's, now stops `build()` and `start()`.
  Bind each device, or its router, at its unicast address.
