---
section: Migration notes
---
- **SC device UUID (#517):** pass a nonzero 16-byte UUID to the `ScHub`
  startup APIs, `ScServerBuilder::device_uuid` and
  `ScTransport::with_device_uuid`, or `sc_device_uuid` and `device_uuid` in
  Python. Generate it before deployment, store it durably and reuse it; see
  the [Python](docs/python-api.md#sc-device-uuid-migration) and
  [Rust](docs/rust-api.md#sc-device-uuid-migration) migration notes.
