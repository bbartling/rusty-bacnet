---
section: Fixed
---
- **Breaking (wire):** the server rejects a confirmed request it can't decode
  with the Reject reason that names the fault, where it answered an Error;
  CreateObject, the list services and SubscribeCOVPropertyMultiple included.
  The client's notification rejects follow the same rule (#1446).
