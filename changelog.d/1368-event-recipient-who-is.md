---
section: Added
---
- **Wire:** an event notification to a Device recipient with no fresh binding sends one Who-Is for it
  and waits the APDU timeout for the I-Am in its own task instead of being skipped; at most one a
  minute per device, none under DCC, a silent device counted once in `device_recipient_unbound` (#1368).
