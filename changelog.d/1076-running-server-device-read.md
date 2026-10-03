---
section: Changed
---
- The running server's Device read view, which wraps every object it serves
  to ReadProperty, ReadPropertyMultiple, ReadRange, `read_local` and the PICS,
  now forwards every read-only `BACnetObject` query to the object it wraps
  (#1076). Before, it forwarded a chosen few, and any other query got the
  trait default instead of the object's answer, as #1046 found for ReadRange.
  It still answers the Device's executor-owned rows itself, and a Device
  offers no frozen COV copy through it. No served value changes: the read
  services ask only queries the view already forwarded. A test reads the
  trait's source and fails when a query has no forwarding check.
