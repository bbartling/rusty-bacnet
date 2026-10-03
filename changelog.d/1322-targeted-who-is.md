---
section: Added
---
- **Wire:** A Command action or Channel member in a device with no fresh binding sends one Who-Is for that device and waits the APDU timeout for its I-Am instead of failing unsent; at most one a minute per device, none while DCC restricts initiation (#1322).
