---
section: Added
---
- **Schedule network writes and Reliability (wire):** a Schedule now accepts
  writes of Weekly_Schedule, Exception_Schedule and Effective_Period, and
  evaluates its own Reliability (#1057, #1056).
  - Writes: WriteProperty, WritePropertyMultiple and `write_local` take the
    whole property or, for the two arrays, one element by index. Writing
    Exception_Schedule's index 0 resizes it, appending empty special events.
    Values are decoded with the shared Clause 21 codecs and checked by the
    same functions as the local setters, and a refused write leaves the
    property unchanged: a time that isn't specific or an event priority
    outside 1 to 16 is VALUE_OUT_OF_RANGE (#1087), a time given twice in one
    list DUPLICATE_ENTRY, an element of another datatype INVALID_DATA_TYPE,
    and a malformed one INVALID_DATA_ENCODING.
    A whole Weekly_Schedule must hold seven days (VALUE_OUT_OF_RANGE) and its
    index 0 is WRITE_ACCESS_DENIED. Exception_Schedule holds at most 1,024
    events, `add_exception` included (RESOURCES / NO_SPACE_TO_WRITE_PROPERTY).
    Before, all three properties answered WRITE_ACCESS_DENIED; the PICS now
    lists them writable.
  - Once a write to a Schedule commits, the server runs that Schedule's pass
    at once, under the same database guard and through the code the 60-second
    tick uses, so a changed value reaches the references, with COV for them,
    without waiting for the next tick.
  - Reliability is CONFIGURATION_ERROR, with FAULT in Status_Flags, while the
    non-NULL values in Weekly_Schedule, Exception_Schedule and
    Schedule_Default are not all of one datatype. It is checked again on every
    change, from the setters or the network, and on the return to service.
    The object clears only a fault it raised, so a value set through
    `set_reliability_internal`, or simulated while Out_Of_Service, stays. A
    misconfigured Schedule keeps writing its references: Clause 12.24.4 makes
    those writes unconditional, and a target that can't take a value refuses
    only that write. Whether each referenced property accepts the datatype is
    judged from the writes (#1086, below).
