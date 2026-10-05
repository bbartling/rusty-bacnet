---
section: Fixed
---
- **Wire:** a Who-Is carrying only one of its two limits is malformed:
  `WhoIsRequest::decode` refuses it and the server drops it, where it used to
  answer as if the request named every device (#1447).
