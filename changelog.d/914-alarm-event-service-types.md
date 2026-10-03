---
section: Changed
---
- Alarm and event service types use the enumerations and bit strings that
  `bacnet-types` already provides instead of raw integers. In `bacnet-services`,
  every `NotificationParameters` variant's `status_flags`, and
  `ChangeOfStatusFlags.referenced_flags`, is a `StatusFlags`. `ChangeOfLifeSafety`
  carries a `LifeSafetyState`, `LifeSafetyMode` and `LifeSafetyOperation`,
  `ChangeOfReliability` a `Reliability`, `ChangeOfTimer` a `TimerState` and an
  `Option<TimerTransition>`, and `AccessEvent` an `AccessEvent`.
  `AcknowledgeAlarmRequest.event_state_acknowledged` is an `EventState`, and
  `EventNotificationRequest` types `event_type`, `notify_type`, `from_state` and
  `to_state`. GetEventInformation's `EventSummary` types `event_state` and
  `notify_type`, holds `acknowledged_transitions` and `event_enable` as
  `bitstring::EventTransitionBits`, and drops `notification_class`: the ACK has
  no such member, so encode ignored it and decode always set 0.
  `AlarmSummaryEntry.acknowledged_transitions` is an `EventTransitionBits`
  rather than an `(unused_bits, data)` pair, so `GetAlarmSummaryAck::encode`
  always writes the canonical three-bit string. Decode already accepted only that
  form. In `bacnet-types`,
  `FaultParameters::FaultLifeSafety.fault_values` is a `Vec<LifeSafetyState>`,
  and `mode_for_reference` becomes `mode_property_reference`, after the
  production's field name. The unused bit-position enum
  `enums::EventTransitionBits` is removed, so a glob import can no longer pick it
  over the bitflags type of the same name. The wire encoding is unchanged, and
  unknown or proprietary values still round-trip. The deprecated
  `BACnetClient::acknowledge_alarm` now takes an `EventState`, and so do the
  Python `acknowledge_alarm_request` and `acknowledge_alarm`, which took an int
  (#914).
