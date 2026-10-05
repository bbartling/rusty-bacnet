---
section: Changed
---
- **Python API:** an AtomicReadFile-ACK with more or fewer records than its
  count, or octets after its data, raises `BacnetError`, where it raised
  `BacnetRejectError` as if the device had rejected the request (#1446).
