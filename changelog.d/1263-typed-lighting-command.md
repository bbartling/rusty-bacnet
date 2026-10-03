---
section: Fixed
---
- **Breaking (wire):** Lighting Output serves and takes Lighting_Command as a
  BACnetLightingCommand checked against its operation, refusing the old octet string,
  and takes the lighting commands a Channel or WriteGroup passes to it (#1263).
