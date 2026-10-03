---
section: Added
---
- **Schedule Present_Value while Out_Of_Service (wire):** a Schedule's
  Present_Value is now writable while Out_Of_Service is TRUE, and each
  written value goes on to the references (#1055).
  - WriteProperty, WritePropertyMultiple and `write_local` take any primitive
    value, NULL included (INVALID_DATA_TYPE otherwise). In service the write
    is WRITE_ACCESS_DENIED, as before for every state; the PICS now lists
    Present_Value writable.
  - The server sends an accepted value to every reference at
    Priority_For_Writing, a NULL relinquishing, in the pass it runs once the
    write commits, with COV for the targets, and does so for every accepted
    write, even of the value already held. Out of service, neither the
    60-second tick nor a change to the schedules replaces the written value.
  - When Out_Of_Service returns to FALSE, the evaluation runs at once and its
    value takes over. A value written in the same WritePropertyMultiple just
    before the return still goes out first.
  - A Reliability simulated meanwhile doesn't hold the write back, and the
    written value's datatype doesn't count towards CONFIGURATION_ERROR.
  - New public hook `BACnetObject::take_owed_schedule_writes` (named
    `take_simulated_schedule_write` until #1088 widened it), which the
    schedule pass calls before `tick_schedule`. A value written on the
    object directly, outside the server's write paths, goes out at the next
    tick; it needs no valid Device clock.
