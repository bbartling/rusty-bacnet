---
section: Changed
---
- The `bacnet-objects` event detectors use typed values too.
  `OutOfRangeDetector`, `ChangeOfStateDetector` and `CommandFailureDetector` hold
  `event_enable` and `acked_transitions` as `bitstring::EventTransitionBits`
  instead of raw `u8` masks, `notify_type` as a `NotifyType` and
  `fault_reliability` as an `Option<Reliability>`. Their `evaluate`, `probe` and
  `tick` take a `Reliability`, and `EventTransition::bit_mask` returns an
  `EventTransitionBits`. `bacnet_objects::event::LimitEnable` is removed in favour
  of the `bacnet_types::bitstring::LimitEnable` bitflags it duplicated: `BOTH` and
  `NONE` become `all()` and `empty()`, `to_bits()`/`from_bits(u8)` become
  `to_bacnet()`/`from_bacnet(&[u8])`, which takes the bit string's content
  octets, and the two bools become the `LOW_LIMIT_ENABLE` and
  `HIGH_LIMIT_ENABLE` flags. `BACnetObject::acknowledge_alarm` and
  `set_acked_transitions_internal` take the transition as an
  `EventTransitionBits`, and so does `EventEnrollmentObject::set_event_enable`.
  Event Enrollment and Alert Enrollment store Event_Enable, Acked_Transitions and
  Notify_Type typed as well, so `AlertEnrollmentObject.event_enable` is an
  `EventTransitionBits`. Property reads and writes put the same bytes on the wire
  (#914).
