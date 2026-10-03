---
section: Fixed
---
- **Breaking Calendar and Schedule evaluation (and Rust API):** Calendar's
  Present_Value now follows the device's local date, and a Schedule now
  calculates its value in the Clause 12.24.4 order and writes it in its own
  datatype (#1029, #1028).
  - Calendar: Present_Value is TRUE when the Device clock's local date matches
    a Date_List entry. It is read from the clock on every read, so it changes
    with the date; before, it stayed whatever the application set. Entries
    match octet by octet: wildcards, odd and even months, the last, odd and
    even day values, open-ended date ranges and every week-of-month form,
    including weeks 6 to 9 counted back from the month's end. A Date_List
    write (WriteProperty, WritePropertyMultiple, AddListElement) with an entry
    out of its Clause 21 range is refused with VALUE_OUT_OF_RANGE and leaves
    the list unchanged; before, it was stored. AddListElement's
    ChangeList-Error names that entry's position, not the first entry the
    list would gain, and RemoveListElement, which has no range error, finds no
    such entry (LIST_ELEMENT_NOT_FOUND). Out of range means a month
    outside 1-14, a week-of-month outside 1-9, a weekday outside 1-7, a day
    outside 1-34, or a date-range end that is neither a specific date nor
    wholly unspecified. `set_present_value` is removed, `add_date_entry`
    returns `Result`, and `is_active_on(day)` answers for any day.
  - Schedule: Present_Value and the writes to its references used to carry an
    Octet String of the time-value's encoding, which a commandable Real target
    refused. Time-values are now typed (`BACnetTimeValue::value` is a
    primitive `PropertyValue`), so a Real schedule writes a Real. Evaluation
    used to apply every exception whatever its period and ignored
    Effective_Period. Now, within Effective_Period, the value is that of the
    best-priority special event in effect today (its inline calendar entry
    matches, or the Calendar it references is TRUE) whose current value is not
    NULL, the lower array index breaking a tie; else today's weekly entry if
    not NULL; else Schedule_Default. Outside the period nothing is calculated
    or written. Entering the period, the first pass after start-up included,
    writes the value even when unchanged. Targets are written at
    Priority_For_Writing (new `set_priority_for_writing`) instead of always
    16, and a NULL relinquishes that slot. Present_Value is calculated even
    with no references. `tick_schedule` now takes the date, the time and a
    Calendar resolver and returns `ScheduleWrite`. The setters return `Result`
    and refuse non-primitive values, repeated or non-specific times and
    out-of-range priorities or calendar entries; Schedule_Default refuses a
    constructed value with INVALID_DATA_TYPE. The schedule encoders in
    `bacnet-encoding` return `Result`.
  - The date rules live in one place, `bacnet_types::calendar`
    (`SpecificDate`, plus `matches`, `contains` and `is_valid` on the calendar
    types), which `ClockFrame::is_valid_actual_datetime` now uses too.
