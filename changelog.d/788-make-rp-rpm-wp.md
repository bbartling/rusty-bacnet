---
section: Fixed
---
- Make RP/RPM/WP batch outcomes attributable to duplicate input occurrences
  with zero-based `request_index` while retaining completion order (#788).
  Python item errors are existing typed `BacnetError` instances, replacing strings;
  genuine Python result-construction failures propagate from the whole call.
  Three private stub-only result shapes describe the returned dictionaries, and
  these methods now correctly advertise `Awaitable` rather than coroutine results.
  Input shapes, concurrency limits and cancellation without partial results remain.
  Rust batch Debug omits encoded write values and successful read ACK payloads.
