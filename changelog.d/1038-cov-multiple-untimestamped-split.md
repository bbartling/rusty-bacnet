---
section: Fixed
commit: ccb3bad0f31b7c630e080525d83b6517e023de01
---
- **Wire:** untimestamped COV-multiple values too large for one notification,
  such as the initial report of a large SubscribeCOVPropertyMultiple, now go
  out in several notifications that each fit (#1038).
