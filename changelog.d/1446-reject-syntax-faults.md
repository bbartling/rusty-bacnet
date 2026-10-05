---
section: Fixed
---
- **Breaking (wire):** a confirmed request the server can't decode now draws
  a Reject naming the fault, for every service, where some drew an Error, and
  some it already rejected get a different reason. The client rejects
  malformed notifications the same way (#1446).
