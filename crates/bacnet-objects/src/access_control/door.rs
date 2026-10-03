use std::sync::Arc;
use std::time::Duration;

use super::door_out_of_service::DoorState;
use super::*;
use crate::traits::MonotonicClock;

// AccessDoorObject (type 30)
// ---------------------------------------------------------------------------

/// Door_Pulse_Time a new door starts with, in tenths of a second (5 s).
pub const DEFAULT_DOOR_PULSE_TIME: u32 = 50;
/// Door_Extended_Pulse_Time a new door starts with, in tenths of a second
/// (15 s).
pub const DEFAULT_DOOR_EXTENDED_PULSE_TIME: u32 = 150;
/// Door_Open_Too_Long_Time a new door starts with, in tenths of a second
/// (30 s).
pub const DEFAULT_DOOR_OPEN_TOO_LONG_TIME: u32 = 300;

/// BACnet Access Door object (type 30).
///
/// Represents a physical door or barrier in an access control system.
/// Present value carries the door command (BACnetDoorValue); Door_Status
/// reports the physical DoorStatus.
///
/// A PULSE_UNLOCK or EXTENDED_PULSE_UNLOCK command holds its priority slot
/// for Door_Pulse_Time or Door_Extended_Pulse_Time and is then relinquished,
/// so the door relocks (Clauses 12.26.4, 12.26.16 and 12.26.17; #1073). The
/// deadline is taken from the database's monotonic clock when the command is
/// written, and the server's monotonic operation task relinquishes the slot
/// at that deadline, the mechanism Binary Lighting Output egress uses. A
/// pulse written below a priority already commanded is relinquished at once,
/// and a pulse time of zero relinquishes at once too. Changing a pulse time
/// leaves an armed deadline as it was.
///
/// While Out_Of_Service is TRUE a client can simulate Door_Status,
/// Lock_Status and Door_Alarm_State by writing them, and the door's own values
/// come back on the return to service (Clause 12.26.9, Table 12-30 footnote 1;
/// #1131). The module `door_out_of_service` has the details.
#[derive(Clone)]
pub struct AccessDoorObject {
    oid: ObjectIdentifier,
    name: String,
    description: String,
    present_value: DoorValue,
    /// Door_Status, Lock_Status and Door_Alarm_State as served: the device's,
    /// or a client's simulation while Out_Of_Service is TRUE.
    state: DoorState,
    /// The device's own door state, put aside while Out_Of_Service is TRUE.
    device_state: Option<DoorState>,
    secured_status: DoorSecuredStatus,
    door_members: Vec<ObjectIdentifier>,
    status_flags: StatusFlags,
    /// Event_State.
    event_state: EventState,
    out_of_service: bool,
    reliability: Reliability,
    /// 16-level priority array for commandable Present_Value.
    priority_array: [Option<DoorValue>; 16],
    relinquish_default: DoorValue,
    /// Door_Pulse_Time, tenths of a second.
    door_pulse_time: u32,
    /// Door_Extended_Pulse_Time, tenths of a second.
    door_extended_pulse_time: u32,
    /// Door_Open_Too_Long_Time, tenths of a second. Stored and served; no
    /// door-open-too-long alarm logic is modelled.
    door_open_too_long_time: u32,
    /// For each priority slot holding a pulse, the monotonic instant it is
    /// relinquished.
    pulse_deadlines: [Option<Duration>; 16],
    monotonic_clock: Option<Arc<MonotonicClock>>,
    /// Elapsed time for a door with no bound clock, advanced by
    /// `advance_time_internal`.
    logical_now: Duration,
}

impl AccessDoorObject {
    /// Create a new Access Door object.
    pub fn new(instance: u32, name: impl Into<String>) -> Result<Self, Error> {
        let oid = ObjectIdentifier::new(ObjectType::ACCESS_DOOR, instance)?;
        Ok(Self {
            oid,
            name: name.into(),
            description: String::new(),
            present_value: DoorValue::LOCK,
            state: DoorState::SECURE,
            device_state: None,
            secured_status: DoorSecuredStatus::SECURED,
            door_members: Vec::new(),
            status_flags: StatusFlags::empty(),
            event_state: EventState::NORMAL,
            out_of_service: false,
            reliability: Reliability::NO_FAULT_DETECTED,
            priority_array: Default::default(),
            relinquish_default: DoorValue::LOCK,
            door_pulse_time: DEFAULT_DOOR_PULSE_TIME,
            door_extended_pulse_time: DEFAULT_DOOR_EXTENDED_PULSE_TIME,
            door_open_too_long_time: DEFAULT_DOOR_OPEN_TOO_LONG_TIME,
            pulse_deadlines: [None; 16],
            monotonic_clock: None,
            logical_now: Duration::ZERO,
        })
    }

    /// Set the Relinquish_Default (#270).
    ///
    /// Table 12-30 types it as BACnetDoorValue, but Clause 12.26.11 admits
    /// only LOCK and UNLOCK: a pulse can't be the resting command. Any other
    /// value, including a `DoorValue::from_raw` outside the production, is
    /// refused with VALUE_OUT_OF_RANGE and the stored default kept. After the
    /// store, Present_Value is resolved anew from the priority array so an
    /// empty array falls back to the new default immediately.
    pub fn set_relinquish_default(&mut self, value: DoorValue) -> Result<(), Error> {
        if !matches!(value, DoorValue::LOCK | DoorValue::UNLOCK) {
            return Err(common::value_out_of_range_error());
        }
        self.relinquish_default = value;
        self.recalculate_present_value();
        Ok(())
    }

    /// Set Door_Pulse_Time, in tenths of a second.
    pub fn set_door_pulse_time(&mut self, tenths: u32) {
        self.door_pulse_time = tenths;
    }

    /// Set Door_Extended_Pulse_Time, in tenths of a second.
    pub fn set_door_extended_pulse_time(&mut self, tenths: u32) {
        self.door_extended_pulse_time = tenths;
    }

    /// Set Door_Open_Too_Long_Time, in tenths of a second.
    pub fn set_door_open_too_long_time(&mut self, tenths: u32) {
        self.door_open_too_long_time = tenths;
    }

    /// Set Door_Status, the open or closed state the door's contact reports.
    ///
    /// While Out_Of_Service is TRUE a client's simulated value keeps being
    /// served, and this one takes over on the return to service.
    pub fn set_door_status(&mut self, status: DoorStatus) {
        self.device_state_mut().door_status = status;
    }

    /// Set Lock_Status, the state the door lock's monitor reports.
    ///
    /// While Out_Of_Service is TRUE a client's simulated value keeps being
    /// served, and this one takes over on the return to service.
    pub fn set_lock_status(&mut self, status: LockStatus) {
        self.device_state_mut().lock_status = status;
    }

    /// Set Door_Alarm_State, the alarm condition the application's door
    /// logic has worked out (Clause 12.26 leaves that to the device).
    ///
    /// A change of the value served triggers a SubscribeCOV notification
    /// (Table 13-1). While Out_Of_Service is TRUE a client's simulated value
    /// keeps being served, and this one takes over on the return to service.
    pub fn set_door_alarm_state(&mut self, state: DoorAlarmState) {
        self.device_state_mut().door_alarm_state = state;
    }

    /// The device's own door state: the one put aside while out of service,
    /// else the one served.
    fn device_state_mut(&mut self) -> &mut DoorState {
        self.device_state.as_mut().unwrap_or(&mut self.state)
    }

    fn recalculate_present_value(&mut self) {
        self.present_value =
            common::recalculate_from_priority_array(&self.priority_array, self.relinquish_default);
    }

    fn monotonic_now(&self) -> Duration {
        self.monotonic_clock
            .as_ref()
            .map_or(self.logical_now, |clock| clock())
    }

    /// Store a command (or a NULL relinquish) at `priority`, arming the
    /// relock deadline for a pulse.
    fn command(&mut self, priority: u8, value: Option<DoorValue>) {
        let index = usize::from(priority - 1);
        self.pulse_deadlines[index] = None;
        let pulse = match value {
            Some(DoorValue::PULSE_UNLOCK) => Some(self.door_pulse_time),
            Some(DoorValue::EXTENDED_PULSE_UNLOCK) => Some(self.door_extended_pulse_time),
            _ => None,
        };
        self.priority_array[index] = match pulse {
            // A pulse below a live command, or of zero length, is
            // relinquished as soon as it is written.
            Some(tenths)
                if tenths == 0 || self.priority_array[..index].iter().any(Option::is_some) =>
            {
                None
            }
            Some(tenths) => {
                let length = Duration::from_millis(u64::from(tenths) * 100);
                self.pulse_deadlines[index] = Some(self.monotonic_now().saturating_add(length));
                value
            }
            None => value,
        };
        self.recalculate_present_value();
    }

    /// Relinquish every pulse whose deadline has passed; `true` when one was.
    fn expire_pulses(&mut self, now: Duration) -> bool {
        let mut expired = false;
        for (slot, deadline) in self
            .priority_array
            .iter_mut()
            .zip(&mut self.pulse_deadlines)
        {
            if deadline.is_some_and(|deadline| now >= deadline) {
                *slot = None;
                *deadline = None;
                expired = true;
            }
        }
        if expired {
            self.recalculate_present_value();
        }
        expired
    }
}

/// Whether `value` is one of the four BACnetDoorValue members. The
/// bacnet-types test `door_value_values_match_clause_21` pins the
/// production's closed-set length, so this bound cannot drift from the enum.
fn is_door_value(value: DoorValue) -> bool {
    value.to_raw() <= DoorValue::EXTENDED_PULSE_UNLOCK.to_raw()
}

/// Decode a BACnetDoorValue write: an Enumerated within the closed set.
fn checked_door_value(value: PropertyValue) -> Result<DoorValue, Error> {
    let PropertyValue::Enumerated(raw) = value else {
        return Err(common::invalid_data_type_error());
    };
    let value = DoorValue::from_raw(raw);
    if !is_door_value(value) {
        return Err(common::value_out_of_range_error());
    }
    Ok(value)
}

/// Decode a door time write: an Unsigned of at most 32 bits.
fn checked_tenths(value: PropertyValue) -> Result<u32, Error> {
    let PropertyValue::Unsigned(raw) = value else {
        return Err(common::invalid_data_type_error());
    };
    common::u64_to_u32(raw)
}

impl BACnetObject for AccessDoorObject {
    fn object_identifier(&self) -> ObjectIdentifier {
        self.oid
    }

    fn object_name(&self) -> &str {
        &self.name
    }

    fn read_property(
        &self,
        property: PropertyIdentifier,
        array_index: Option<u32>,
    ) -> Result<PropertyValue, Error> {
        if let Some(result) = read_common_properties!(self, property, array_index) {
            return result;
        }
        match property {
            p if p == PropertyIdentifier::OBJECT_TYPE => {
                Ok(PropertyValue::Enumerated(ObjectType::ACCESS_DOOR.to_raw()))
            }
            p if p == PropertyIdentifier::PRESENT_VALUE => {
                Ok(PropertyValue::Enumerated(self.present_value.to_raw()))
            }
            p if p == PropertyIdentifier::DOOR_STATUS => {
                Ok(PropertyValue::Enumerated(self.state.door_status.to_raw()))
            }
            p if p == PropertyIdentifier::LOCK_STATUS => {
                Ok(PropertyValue::Enumerated(self.state.lock_status.to_raw()))
            }
            p if p == PropertyIdentifier::SECURED_STATUS => {
                Ok(PropertyValue::Enumerated(self.secured_status.to_raw()))
            }
            p if p == PropertyIdentifier::DOOR_ALARM_STATE => Ok(PropertyValue::Enumerated(
                self.state.door_alarm_state.to_raw(),
            )),
            p if p == PropertyIdentifier::DOOR_MEMBERS => Ok(PropertyValue::List(
                self.door_members
                    .iter()
                    .map(|oid| PropertyValue::ObjectIdentifier(*oid))
                    .collect(),
            )),
            p if p == PropertyIdentifier::EVENT_STATE => {
                Ok(PropertyValue::Enumerated(self.event_state.to_raw()))
            }
            p if p == PropertyIdentifier::PRIORITY_ARRAY => {
                common::read_priority_array!(self, array_index, |v: DoorValue| {
                    PropertyValue::Enumerated(v.to_raw())
                })
            }
            p if p == PropertyIdentifier::RELINQUISH_DEFAULT => {
                Ok(PropertyValue::Enumerated(self.relinquish_default.to_raw()))
            }
            p if p == PropertyIdentifier::DOOR_PULSE_TIME => {
                Ok(PropertyValue::Unsigned(self.door_pulse_time.into()))
            }
            p if p == PropertyIdentifier::DOOR_EXTENDED_PULSE_TIME => Ok(PropertyValue::Unsigned(
                self.door_extended_pulse_time.into(),
            )),
            p if p == PropertyIdentifier::DOOR_OPEN_TOO_LONG_TIME => {
                Ok(PropertyValue::Unsigned(self.door_open_too_long_time.into()))
            }
            // NULL while Present_Value comes from Relinquish_Default
            // (Clause 12.26.39).
            p if p == PropertyIdentifier::CURRENT_COMMAND_PRIORITY => {
                Ok(common::current_command_priority(&self.priority_array))
            }
            _ => Err(common::unknown_property_error()),
        }
    }

    fn write_property(
        &mut self,
        property: PropertyIdentifier,
        _array_index: Option<u32>,
        value: PropertyValue,
        priority: Option<u8>,
    ) -> Result<(), Error> {
        // The door's entry edge is always seen (it starts in service and only
        // this write moves Out_Of_Service), so there is no fallback state.
        if let Some(result) = common::write_out_of_service_with_restore(
            &mut self.out_of_service,
            &mut self.state,
            &mut self.device_state,
            None,
            property,
            &value,
        ) {
            return result;
        }
        if let Some(result) = common::write_description(&mut self.description, property, &value) {
            return result;
        }
        if let Some(result) = self.state.write(self.out_of_service, property, &value) {
            return result;
        }
        match property {
            // A command (or a NULL relinquish) at the write priority, 16 when
            // absent; Present_Value is then resolved from the priority array.
            p if p == PropertyIdentifier::PRESENT_VALUE => {
                let priority = priority.unwrap_or(16);
                if !(1..=16).contains(&priority) {
                    return Err(common::value_out_of_range_error());
                }
                let value = match value {
                    PropertyValue::Null => None,
                    other => Some(checked_door_value(other)?),
                };
                self.command(priority, value);
                Ok(())
            }
            // Table 12-30 carries Relinquish_Default R (BACnetDoorValue) for
            // the commandable Access Door; the standard permits writability.
            p if p == PropertyIdentifier::RELINQUISH_DEFAULT => {
                self.set_relinquish_default(checked_door_value(value)?)
            }
            p if p == PropertyIdentifier::DOOR_PULSE_TIME => {
                self.door_pulse_time = checked_tenths(value)?;
                Ok(())
            }
            p if p == PropertyIdentifier::DOOR_EXTENDED_PULSE_TIME => {
                self.door_extended_pulse_time = checked_tenths(value)?;
                Ok(())
            }
            p if p == PropertyIdentifier::DOOR_OPEN_TOO_LONG_TIME => {
                self.door_open_too_long_time = checked_tenths(value)?;
                Ok(())
            }
            _ => Err(crate::common::unhandled_write_error(
                self.property_metadata().as_ref(),
                property,
                _array_index,
            )),
        }
    }

    fn property_metadata(&self) -> Cow<'_, [crate::property_metadata::PropertyMetadata]> {
        super::metadata_topology::for_access_door_object(self)
    }

    fn property_list(&self) -> Cow<'static, [PropertyIdentifier]> {
        crate::property_metadata::property_list_from_metadata(self.property_metadata().as_ref())
    }

    fn supports_cov(&self) -> bool {
        true
    }

    fn advance_time_internal(&mut self, elapsed: Duration) -> bool {
        self.logical_now = self.logical_now.saturating_add(elapsed);
        self.expire_pulses(self.logical_now)
    }

    fn bind_monotonic_clock_internal(&mut self, clock: Option<Arc<MonotonicClock>>) {
        self.monotonic_clock = clock;
    }

    fn advance_monotonic_time_internal(&mut self, now: Duration) -> bool {
        self.expire_pulses(now)
    }

    fn next_monotonic_deadline_internal(&self) -> Option<Duration> {
        self.pulse_deadlines.iter().flatten().min().copied()
    }

    fn cov_snapshot_internal(&self) -> Option<Box<dyn BACnetObject>> {
        Some(Box::new(self.clone()))
    }
}

// ---------------------------------------------------------------------------
