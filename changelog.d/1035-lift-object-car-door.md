---
section: Fixed
---
- The Lift object's Car_Door_Status and Landing_Door_Status now take
  WriteProperty while Out_Of_Service is TRUE, so a test tool can simulate the
  car, as the Lift's Out_Of_Service description asks (#1035). A write sets the
  whole array or one element; Car_Door_Status elements are BACnetDoorStatus
  values and Landing_Door_Status elements BACnetLandingDoorStatus frames. The
  size, the car door count, stays the application's: a write of index 0 fails
  with WRITE_ACCESS_DENIED, a whole array of another size with
  VALUE_OUT_OF_RANGE, and an index past the last door with
  INVALID_ARRAY_INDEX, so the two arrays keep the same size. A reserved door
  status or a floor number above 255 fails with VALUE_OUT_OF_RANGE and an
  undecodable frame with INVALID_DATA_ENCODING, all without changing either
  array. In service both stay read-only and refuse writes with
  WRITE_ACCESS_DENIED. Their property metadata and PICS rows now mark them
  writable while out of service. The Lift's other status properties, and all
  of the Escalator's, already took writes. `decode_landing_door_status` in
  `bacnet-encoding` now reports a well-formed floor number above 255 or door
  status above 32 bits as `Error::OutOfRange`, as `decode_landing_call_status`
  does, instead of a decoding error.
