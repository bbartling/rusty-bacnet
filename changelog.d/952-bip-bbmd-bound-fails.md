---
section: Migration notes
---
- **Wildcard BBMD (#952, #937):** a B/IP BBMD bound to `0.0.0.0` fails
  `start()` unless exactly one BDT row names a local address at the bound port
  or the default-route address is usable, and a loaded persisted BDT decides
  alone. Bind the interface address to avoid this; see the
  [BBMD section](docs/rust-api.md#bbmd).
