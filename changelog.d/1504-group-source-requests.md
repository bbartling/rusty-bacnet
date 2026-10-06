---
section: Fixed
---
- **Wire:** The server, client and endpoint ignore a confirmed request whose
  link-layer source is a group address, so no reply or confirmed COV
  notification goes to a group. The server and client count it in the new
  `group_source_request_drops()` (#1504).
