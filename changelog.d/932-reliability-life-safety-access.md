---
section: Changed
---
- Reliability and the life-safety, access-control and elevator-group object
  fields are typed as well. Every `bacnet-objects` object that stores
  Reliability holds a `Reliability` rather than a `u32`, so
  `BACnetObject::set_reliability_internal` takes a `Reliability`, and
  `ReliabilityEvaluation::Changed` and the `bacnet-server`
  `fault_detection::ReliabilityChange` carry `old_reliability` and
  `new_reliability` as `Reliability`. Life Safety Point and Zone store
  Present_Value as `LifeSafetyState`, Mode as `LifeSafetyMode`, Silenced as
  `SilencedState` and Operation_Expected as `LifeSafetyOperation`, and the Point
  stores Tracking_Value as `LifeSafetyState` too. Both objects'
  `set_present_value` and `set_mode`, and the Point's `set_tracking_value`, take
  the typed value instead of a `u32`. Access Door stores
  Door_Status, Lock_Status, Secured_Status and Door_Alarm_State as `DoorStatus`,
  `LockStatus`, `DoorSecuredStatus` and `DoorAlarmState`. Access Point stores
  Present_Value and Access_Event as `AccessEvent`, Access User stores
  Present_Value and User_Type as `AccessUserType`, Access Zone's Present_Value is
  an `AccessZoneOccupancyState` and Elevator Group's Group_Mode a
  `LiftGroupMode`. Writes accept exactly what they accepted before: Reliability
  still refuses the reserved values and anything above 65535, and the other
  enumerated writes still store any value. Reads, COV and event payloads put the
  same enumerated values on the wire, proprietary and unnamed values still
  round-trip, and the Python API is unchanged (#932).
