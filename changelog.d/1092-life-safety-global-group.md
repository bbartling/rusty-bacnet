---
section: Added
---
- **Breaking Life Safety and Global Group required rows (wire and Rust API):**
  Life Safety Point, Life Safety Zone and Global Group now serve required rows
  of their Clause 12 tables that they lacked. Each new row is in Property_List,
  the property metadata, RPM ALL and REQUIRED and the PICS (#1092).
  - Life Safety Point (Table 12-18) and Zone (Table 12-19): Accepted_Modes, a
    read-only list of the modes a WriteProperty or WritePropertyMultiple of
    Mode may select. It starts as every standard LifeSafetyMode, and
    `set_accepted_modes` replaces it. A network Mode write naming a mode off
    the list now fails with PROPERTY / VALUE_OUT_OF_RANGE and leaves Mode
    alone; before, any Enumerated was stored. The local `set_mode` is not
    checked against the list.
  - Life Safety Zone: Tracking_Value, read-only like the Point's and set with
    `set_tracking_value` or a reset commit, so `LifeSafetyZoneResetContext`
    and `LifeSafetyZoneResetCommit` gain a `tracking_value` field. As on the
    Point, it can be subscribed with SubscribeCOVProperty, which used to fail
    with NOT_COV_PROPERTY, and a reset that changes it notifies.
  - Global Group (Table 12-57): Event_State, which stays NORMAL because the
    object has no intrinsic reporting, and Member_Status_Flags, the OR of the
    Status_Flags values held in Present_Value for members that reference
    Status_Flags. It is worked out from Present_Value on every read, so it
    follows each update the application makes there.
