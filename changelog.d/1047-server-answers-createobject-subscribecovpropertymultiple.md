---
section: Fixed
commit: 0f43456afa2ae49d066aa2875d2db1524e0e4966
---
- **Breaking (wire):** the server answers CreateObject and
  SubscribeCOVPropertyMultiple errors with their Clause 21 error bodies
  instead of a plain class and code (#1047).
