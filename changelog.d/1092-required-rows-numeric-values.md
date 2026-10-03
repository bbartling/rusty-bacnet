---
section: Added
---
- **Breaking required rows on the numeric values, the Pulse Converter and
  the lighting objects (wire and Rust API):** each object now serves the
  required rows its Clause 12 table lists and it lacked (#1092). They join
  Property_List, RPM ALL and REQUIRED (COV_Period, below, OPTIONAL), and the
  PICS.
  - Integer Value, Positive Integer Value and Large Analog Value serve Units,
    a BACnetEngineeringUnits enumeration that starts at NO_UNITS. It is
    read-only over the network, like the analog objects' Units; the new
    `set_units` sets it (a value above 65535 fails with VALUE_OUT_OF_RANGE)
    and `units()` reads it back.
  - The Pulse Converter serves Count and Count_Before_Change (Unsigned) and
    Update_Time and Count_Change_Time (BACnetDateTime), all read-only, plus
    COV_Period, a constant 0 that its COV support makes required; zero means
    the server sends no periodic notifications. Count is now the object's
    state: the new `add_pulses` accumulates input and stamps Update_Time
    from the Device clock, and `count()` reads it. In service, Present_Value
    is Count times Scale_Factor; before, it was a stored value only an
    out-of-service write could change. A write of Adjust_Value now does what
    Clause 12.23.13 describes instead of only storing the value: it keeps the
    old Count in Count_Before_Change, takes the whole quotient of the value
    over Scale_Factor off Count, and stamps Count_Change_Time. A write that
    would take Count below zero or past its range, or that meets a zero
    Scale_Factor, fails with VALUE_OUT_OF_RANGE and changes nothing, and so
    does any change that would scale Count past the largest REAL. Going out
    of service holds Present_Value where it was and makes it writable, while
    Count keeps counting; back in service it follows Count again. Timestamps
    are unspecified until the first change, or when there is no clock.
    SubscribeCOV notifications for a Pulse Converter carry Update_Time after
    Present_Value and Status_Flags, as Table 13-1 lists; it is reported but
    does not trigger a notification. The type moved to its own module,
    still exported as `bacnet_objects::accumulator::PulseConverterObject`.
  - Lighting Output serves Default_Ramp_Rate (default 100.0 percent per
    second) and Default_Step_Increment (default 1.0 percent). Both take
    WriteProperty, and the new `set_default_ramp_rate` and
    `set_default_step_increment` setters, for a REAL from 0.1 to 100.0; a
    value outside that range fails with VALUE_OUT_OF_RANGE and another
    datatype with INVALID_DATA_TYPE. Both lighting objects serve
    Current_Command_Priority, the Priority_Array slot
    Present_Value comes from, or NULL while Relinquish_Default is in effect,
    through the helper the other commandable objects use. It is read-only.
