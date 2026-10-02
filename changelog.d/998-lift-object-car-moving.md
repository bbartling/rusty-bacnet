---
section: Fixed
---
- The Lift object's Car_Moving_Direction now accepts every
  BACnetLiftCarDirection value (#998). Its write check admitted only 0 to 3,
  numbered as if 1 were STOPPED and 3 DOWN, so it refused DOWN (4),
  UP_AND_DOWN (5) and the proprietary values 1024 to 65535 that Clause 23.1
  allows for this enumeration. It now accepts the six named values and that range, and still
  refuses the reserved values 6 to 1023 and anything above 65535 with
  VALUE_OUT_OF_RANGE, leaving the stored value unchanged. A new Lift now reads
  STOPPED (2), as intended, instead of NONE (1). The value is stored as
  `LiftCarDirection`, as #932 did for the other enumerated fields.
