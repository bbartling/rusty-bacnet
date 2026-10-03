---
section: Changed
---
- GetEnrollmentSummary and the stored Event_State are typed as well.
  `GetEnrollmentSummaryRequest.acknowledgment_filter` is an
  `enums::AcknowledgmentFilter` (`ALL`, `ACKED`, `NOT_ACKED`) instead of a `u32`.
  `try_encode` still refuses an undefined value and decode still rejects one. The
  `bacnet-server` GetEnrollmentSummary handler reads Acked_Transitions into an
  `EventTransitionBits`, and its Event Enrollment evaluator carries the
  Event_Type it reads as an `EventType`. In `bacnet-objects`, every object that
  stores Event_State holds an `EventState` rather than a `u32`: Event and Alert
  Enrollment, Access Door, Access Point, Accumulator, Pulse Converter, Color,
  Color Temperature, Event Log, Life Safety Point and Zone, Load Control and
  Timer. Event Enrollment stores Event_Type as an `EventType`, so
  `EventEnrollmentObject::new` takes an `EventType` and `set_event_state` an
  `EventState`. The Python `BACnetServer.add_event_enrollment` takes an
  `EventType`, defaulting to `EventType.CHANGE_OF_BITSTRING`, instead of an int,
  and the Python `get_enrollment_summary` takes the new `AcknowledgmentFilter`
  class, defaulting to `AcknowledgmentFilter.ALL`, instead of an int.
  Property reads return the same enumerated values (#930).
