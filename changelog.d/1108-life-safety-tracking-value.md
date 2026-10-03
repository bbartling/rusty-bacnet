---
section: Added
---
- **Life Safety Tracking_Value and Reliability while Out_Of_Service (wire):**
  a Life Safety Point or Zone now takes writes of Tracking_Value and
  Reliability while Out_Of_Service is TRUE, as footnote 1 of Tables 12-18 and
  12-19 asks (#1108).
  - WriteProperty, WritePropertyMultiple and `write_local` take an Enumerated:
    for Tracking_Value a standard BACnetLifeSafetyState or one from 256 to
    65535, for Reliability a named value or one from 64 to 65535. Any other
    number is VALUE_OUT_OF_RANGE, another datatype INVALID_DATA_TYPE, and the
    property keeps its value. In service both stay WRITE_ACCESS_DENIED. The
    property metadata marks both WhenOutOfService, so the PICS now lists them
    writable.
  - Entering out of service puts the object's own Tracking_Value and
    Reliability aside, and the return to service brings them back, dropping
    the simulated values. Meanwhile a Tracking_Value from `set_tracking_value`
    or a reset commit replaces the value put aside rather than the one served.
  - New: both objects implement `set_reliability_internal`, so the
    application can report a fault in service. It is refused while
    Out_Of_Service is TRUE, as on the other Reliability carriers.
  - A committed simulation write notifies through the Life Safety COV
    snapshots like any other write: Tracking_Value property subscribers for a
    new Tracking_Value, and every subscriber when Reliability changes the
    FAULT bit of Status_Flags. Present_Value, Silenced and Operation_Expected
    don't follow a simulated Tracking_Value: the object doesn't derive them
    from it. A reset executor's context carries the Tracking_Value served.
    No event follows either, since CHANGE_OF_LIFE_SAFETY monitors
    Present_Value (Clause 13.3.8) and these objects run no intrinsic
    reporting.
