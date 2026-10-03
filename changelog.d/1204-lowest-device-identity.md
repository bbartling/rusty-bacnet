---
section: Changed
---
- With several Devices in the database, Audit Reporters, Audit Log receipt and
  forwarding, endpoint Device writes and the standalone PICS treat the lowest
  as this device, as wildcard reads already do, where they used to refuse or
  pick any one ([details](docs/rust-api.md#databases-with-several-devices), #1204).
