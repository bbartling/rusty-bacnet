---
section: Fixed
---
- **Breaking (wire, Rust and Python API):** service decoders, `IHaveRequest`,
  `AtomicWriteFileAck` and `PrivateTransferAck` included, refuse trailing
  octets: the server refuses or drops such requests, the client ignores such an
  I-Am, and `confirmed_private_transfer` raises `BacnetError` (#1411).
