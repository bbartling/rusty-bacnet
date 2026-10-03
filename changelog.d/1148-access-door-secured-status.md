---
section: Fixed
---
- **Access Door Secured_Status is derived (wire):** an Access Door's
  Secured_Status used to read SECURED whatever the door did. Each read now
  works it out from what the door serves (Clause 12.26.14, #1148).
  - SECURED needs a door commanded LOCK, not IN_ALARM, with Door_Status CLOSED
    or UNUSED and Lock_Status LOCKED or UNUSED. Any input that misses gives
    UNSECURED, so an UNLOCK, PULSE_UNLOCK or EXTENDED_PULSE_UNLOCK reads
    UNSECURED until it is relinquished or relocks.
  - UNKNOWN comes from a Door_Status or Lock_Status that reads UNKNOWN or a
    fault (DOOR_FAULT, LOCK_FAULT), the door's own monitor unable to tell.
    It applies only when no other input already gives UNSECURED.
  - While Out_Of_Service is TRUE the simulated Door_Status and Lock_Status
    count, and the return to service moves Secured_Status back with the
    device's values. Masked_Alarm_Values isn't served yet (#1149), so it
    doesn't count against the door. Secured_Status isn't a Table 13-1 COV
    value for the door, so it sends no report.
