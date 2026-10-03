---
section: Added
---
- **Schedule reference and priority writes, and the reference half of
  Reliability (wire, breaking):** List_Of_Object_Property_References and
  Priority_For_Writing are now network-writable, and a target that refuses
  the schedule's datatype faults the Schedule (#1088, #1086).
  - WriteProperty, WritePropertyMultiple and `write_local` take
    Priority_For_Writing as an Unsigned from 1 to 16 (VALUE_OUT_OF_RANGE
    otherwise), and the reference list whole, in the form a read returns. A
    member that names a Device is OPTIONAL_FUNCTIONALITY_NOT_SUPPORTED, the
    error Clause 12.24.10 gives a Schedule that writes only objects in its
    own device, as this one does; a member of another datatype is
    INVALID_DATA_TYPE, a malformed one INVALID_DATA_ENCODING, and more than
    1,024 members RESOURCES / NO_SPACE_TO_WRITE_PROPERTY. A refused write
    changes nothing. Before, both properties answered WRITE_ACCESS_DENIED;
    the PICS now lists them writable. (#1121 and #1122 since added the list
    services and members naming this device.)
  - After a change, the pass the write triggers sends the current
    Present_Value to the new list at the new priority, if the Schedule is
    writing at all (in service, only inside Effective_Period). It also
    relinquishes, with a NULL at the old priority, every slot the Schedule
    holds that the change leaves behind: a dropped reference, or every
    reference when the priority moves. A Schedule holds a slot from a write of
    a non-NULL value until it leaves its Effective_Period, so a Schedule out
    of season clears nothing that another Schedule on the same targets may now
    command (Clause 12.24.6).
  - Reliability is also CONFIGURATION_ERROR while a referenced property
    refused, with INVALID_DATA_TYPE or DATATYPE_NOT_SUPPORTED, the last value
    of the schedule's datatype written to it. The fault shows at the first
    such write, clears when that target takes a value or leaves the list, and
    combines with the contents check under the same rule: the object clears
    only a fault it raised. A NULL, or a value of another datatype written
    while Out_Of_Service, counts for nothing. The Schedule keeps writing its
    other targets.
  - Breaking: `ScheduleObject::add_object_property_reference` returns
    `Result` (the 1,024 cap), and `set_object_property_references` replaces
    the list. `BACnetObject::take_owed_schedule_writes` returns every owed
    write, relinquishments first, as a `Vec`. The new
    `BACnetObject::complete_schedule_write` hook takes one
    `ScheduleTargetOutcome` per reference after each write; the bundled
    server calls it.
