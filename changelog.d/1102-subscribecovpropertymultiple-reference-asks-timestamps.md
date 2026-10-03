---
section: Fixed
commit: 6a8c79a18934f40e828a40902e58eb3beaa1e810
---
- **Breaking (wire):** a SubscribeCOVPropertyMultiple reference that asks for
  timestamps while the Device has no valid clock is refused on its own, in
  request order, instead of refusing the whole request (#1102).
