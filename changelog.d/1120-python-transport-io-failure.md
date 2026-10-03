---
section: Changed
---
- **Python: a transport I/O failure raises `BacnetTransportError`, an `OSError` with `errno` (#1120):**
  a bind, listen, dial or socket failure (B/IP and B/IPv6 binds, `ScHub.start`,
  SC connects, the endpoint pre-bind probes) used to raise
  `BacnetError("transport error: ...")`, so the error kind was only in the
  message. It now raises `BacnetTransportError`, a subclass of both
  `BacnetError` and `OSError`: `errno` is the operating system's code, or the
  code for the `io::ErrorKind` when the error has none, or `None`; `strerror`
  is the message. `except OSError as e: e.errno == errno.EADDRINUSE` works
  (Windows can report `WSAEACCES` for a UDP port another socket holds), and
  existing `except BacnetError` handlers still catch it. The exception text
  loses its `transport error:` prefix.
