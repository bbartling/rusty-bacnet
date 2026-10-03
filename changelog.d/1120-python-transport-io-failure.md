---
section: Changed
commit: b9ae0e2ef2b38111252b47cddaf550d520522de2
---
- **Breaking (Python API):** a transport I/O failure raises
  `BacnetTransportError`, a subclass of both `BacnetError` and `OSError` that
  carries `errno`, and the message loses its `transport error:` prefix
  (#1120).
