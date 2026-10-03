---
section: Fixed
---
- **Breaking (wire):** a SubscribeCOVPropertyMultiple reference that asks for
  timestamps while the Device has no valid clock is refused on its own, in
  request order, instead of refusing the whole request (#1102).
