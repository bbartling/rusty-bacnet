---
section: Added
---
- **Wire:** an event notification to a Device recipient with no fresh binding sends one Who-Is and
  waits, behind the ones already waiting for that device, up to the APDU timeout (a minute at most)
  for the I-Am; at most 1,024 wait, none under DCC, a silent device counted once (#1368).
