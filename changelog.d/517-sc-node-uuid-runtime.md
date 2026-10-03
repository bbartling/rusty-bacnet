---
section: Changed
---
- **SC node UUID runtime compatibility break:** `ScServerBuilder` now requires
  `.device_uuid([u8; 16])`; Python `BACnetClient`/`BACnetServer` require the new
  keyword-only `sc_device_uuid` for SC. Missing/all-zero UUIDs fail before dialing;
  Python also rejects wrong lengths at construction after credential-presence
  checks, before file I/O. Accepted bytes are retained unchanged across supported
  lifecycles/reconnect; old Python positional slots and non-SC behavior remain.
  Callers must provision before deployment, durably store, and reuse the same UUID
  for the device's lifetime, never share it between distinct devices or generate
  it per start. There is no generation/storage backend, version/variant enforcement,
  or detection of changed persisted identity. Rust client identity policy, hubs,
  raw transport defaults, wire admission and VMAC policy are unchanged. Same-UUID
  hub replacement is intentional. #517 remained open at slice time for residual identity work;
  no lifetime-storage or full-profile guarantee. See the
  [Python](docs/python-api.md#sc-device-uuid-migration) and
  [Rust](docs/rust-api.md#sc-device-uuid-migration) migration contracts.
