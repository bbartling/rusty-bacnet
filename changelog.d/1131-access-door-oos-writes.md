---
section: Fixed
---
- **Breaking Access Door out-of-service writes (wire):** an Access Door now
  takes writes of Door_Status, Lock_Status and Door_Alarm_State while
  Out_Of_Service is TRUE, the three rows footnote 1 of Table 12-30 marks, so a
  client can simulate the door (#1131). Before, all three refused every write.
  - WriteProperty and WritePropertyMultiple take an Enumerated: a named
    BACnetDoorStatus or one from 1024 to 65535, a named BACnetLockStatus (the
    production is closed), or a named BACnetDoorAlarmState or one from 256 to
    65535. Any other number is VALUE_OUT_OF_RANGE, another datatype
    INVALID_DATA_TYPE, and the property keeps its value. In service the three
    stay WRITE_ACCESS_DENIED. The property metadata marks them
    WhenOutOfService, so the PICS now lists them writable.
  - Entering out of service puts the door's own three values aside, and the
    return to service serves them again, dropping the simulated values.
    Meanwhile a value from `AccessDoorObject::set_door_alarm_state` replaces
    the one put aside rather than the one served.
  - New: `AccessDoorObject::set_door_status` and `set_lock_status`, which
    follow the same rule. Like the other object setters they reach the object
    only before the server holds it.
  - A simulated Door_Alarm_State sends the SubscribeCOV report #1061 added,
    and so does the return to service when it restores a different value.
    The pulse relock keeps to its timer and leaves the simulated values
    alone, and no event follows, since the door runs no intrinsic reporting.
    Reliability isn't among the footnoted rows and stays read-only: the door
    has no fault algorithm that could move it off NO_FAULT_DETECTED.
