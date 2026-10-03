---
section: Migration notes
---
- **Typed alarm values (#914, #930, #932):** replace raw integers with the
  `bacnet-types` enumerations (`EventState`, `Reliability`, `LifeSafetyState`
  and so on) and bit strings (`StatusFlags`, `EventTransitionBits`,
  `DaysOfWeek`), and the objects' `LimitEnable` with
  `bacnet_types::bitstring::LimitEnable`. Python's `acknowledge_alarm`,
  `add_event_enrollment` and `get_enrollment_summary` take enum values.
