---
section: Fixed
---
- **COV reports for the rest of Table 13-1 (wire):** SubscribeCOV now covers
  every object type the COV criteria table (Clause 13.1, Table 13-1) lists
  that the stack builds, and each report carries the values that type's row
  names after Present_Value and Status_Flags (#1061). A change of a value
  marked as a trigger sends a report on its own; the others only ride along.
  - Access Door reports now carry Door_Alarm_State, and its change triggers a
    report. Before, neither happened.
  - Access Point, Credential Data Input and Load Control took no SubscribeCOV
    (OPTIONAL_FUNCTIONALITY_NOT_SUPPORTED); now they do, and they take
    SubscribeCOVProperty and SubscribeCOVPropertyMultiple too.
  - An Access Point has no Present_Value, so its report starts with
    Access_Event, then Status_Flags, Access_Event_Tag and Access_Event_Time.
    Only an Access_Event_Time or Status_Flags change sends one. The Device's
    Active_COV_Subscriptions already named Access_Event for these
    subscriptions.
  - A Credential Data Input report carries Update_Time, a trigger.
  - A Load Control report carries Requested_Shed_Level, Start_Time and
    Shed_Duration, each a trigger.
  - Rows the objects don't serve yet are left out of the report: Access
    Point's Access_Event_Credential and Access_Event_Authentication_Factor,
    and Load Control's Duty_Window (#1092).
  - New setters for values that have no network write route:
    `AccessDoorObject::set_door_alarm_state`,
    `AccessPointObject::set_access_event` and
    `CredentialDataInputObject::set_update_time`. Like the other object
    setters they reach the object only before the server holds it.
  - `BACnetObject::cov_reported_properties` lists the new rows by default.
    The Pulse Converter's Update_Time (#1092) was already reported; a pulse
    that moves only Update_Time still sends nothing.
