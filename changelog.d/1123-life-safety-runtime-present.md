---
section: Added
---
- **Life Safety runtime Present_Value and Tracking_Value (breaking API):** once
  a server holds a Life Safety Point or Zone, the application can now change
  its Present_Value and Tracking_Value (#1123). Before, only a reset commit
  could, and `set_present_value_local` answered
  OPTIONAL_FUNCTIONALITY_NOT_SUPPORTED for these objects.
  - Point and Zone implement `BACnetObject::set_present_value_internal`, so
    `BACnetServer::set_present_value_local` (Python:
    `BACnetServer.set_present_value_local`) takes them. The new
    `BACnetObject::set_tracking_value_internal` hook (default:
    OPTIONAL_FUNCTIONALITY_NOT_SUPPORTED) backs the new
    `BACnetServer::set_tracking_value_local` (Python:
    `BACnetServer.set_tracking_value_local`). Custom wrappers that forward
    every trait method need the new one.
  - Both take an Enumerated BACnetLifeSafetyState, standard or from 256 to
    65535, the range a reset commit already enforces. Another number fails
    with VALUE_OUT_OF_RANGE and another datatype with INVALID_DATA_TYPE,
    leaving the object as it was; an unknown object fails with UNKNOWN_OBJECT
    and any other object type with OPTIONAL_FUNCTIONALITY_NOT_SUPPORTED.
  - Each sets only its own property. Silenced and Operation_Expected stay
    put and the object never derives one value from the other, so latching
    Present_Value until reset stays the application's rule (Clauses 12.15.4
    and 12.16.4 leave it to the implementation); a reset executor's context
    sees the values the route left.
  - Present_Value has no out-of-service footnote, so it is taken whether or
    not Out_Of_Service is TRUE. A Tracking_Value sent while it is TRUE
    replaces the value set aside, as #1108 does for `set_tracking_value`, and
    is served and notified on the return to service.
  - Both go through the server's local write path: a Present_Value change
    notifies SubscribeCOV and Present_Value property subscribers, a
    Tracking_Value change only its property subscribers, and the post-write
    event pass runs as for every other `set_present_value_local` caller
    (the built-in objects run no intrinsic reporting, so it raises nothing).
