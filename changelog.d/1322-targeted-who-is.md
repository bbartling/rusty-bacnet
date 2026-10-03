---
section: Added
---
- **Wire:** A Command action or Channel member in a device with no fresh binding sends one Who-Is for it, globally or where its last I-Am came from, and waits the APDU timeout for the I-Am instead of failing unsent; at most one a minute per device, none while DCC restricts initiation (#1322).
