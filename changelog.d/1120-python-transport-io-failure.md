---
section: Changed
---
- **Breaking (Python API):** a transport I/O failure raises
  `BacnetTransportError`, a subclass of both `BacnetError` and `OSError` that
  carries `errno`, and the message loses its `transport error:` prefix
  (#1120).
