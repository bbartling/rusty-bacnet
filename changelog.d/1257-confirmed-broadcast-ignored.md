---
section: Fixed
---
- **Breaking (wire):** The server ignores a confirmed request sent by broadcast or multicast,
  whatever the service, instead of executing and answering it, so the Notification Forwarder never
  forwards one (#1257).
