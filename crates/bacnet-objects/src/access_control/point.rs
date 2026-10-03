use std::sync::Arc;

use bacnet_types::enums::AuthorizationMode;

use super::point_authorization::Authorization;
use super::*;
use crate::clock::ClockReader;

// AccessPointObject (type 33)
// ---------------------------------------------------------------------------

/// BACnet Access Point object (type 33).
///
/// Represents an access point (reader/controller at a door) in an access control system.
/// The most recent access event is Access_Event; Table 12-36 has no
/// Present_Value row, so the object serves none (#1064).
///
/// Each change of Out_Of_Service is an access event of the point's own
/// (Clause 12.31.8; #1248): entering out of service records OUT_OF_SERVICE
/// and the return to service OUT_OF_SERVICE_RELINQUISHED. Recording one
/// follows Clause 12.31.27.1, which moves Access_Event_Tag on when an event
/// starts a new access transaction and stamps Access_Event_Time with the
/// current date and time. The introduction to Clause 12.31 counts an
/// operator action as an access transaction, so each change of
/// Out_Of_Service starts a new one: the tag moves on by one (wrapping at the
/// top of the Unsigned range), and the time comes from the Device clock. A
/// write that leaves Out_Of_Service as it was, NULL included, records
/// nothing. No credential belongs to an edge, so each one stores the
/// no-credential reference in Access_Event_Credential (Clause 12.31.30).
/// The point doesn't serve Access_Event_Authentication_Factor.
///
/// Authentication_Status is the status the application reports for its
/// authentication process (Clause 12.31.9; #1284), READY until it reports
/// another. While Out_Of_Service is TRUE no authentication runs, so the
/// property reads DISABLED; the reported status is kept and served again on
/// the return to service.
///
/// With no usable Device clock the time takes the BACnetTimeStamp
/// sequence-number form (Clauses 12.31.29 and 21.6) and holds the new tag:
/// the tag itself while it fits the form's 1 to 65535, and past that the tag
/// folded back into that range, so successive edges still differ and none
/// reads 0, the value of an update time with no update yet.
///
/// Access_Event_Time is the Table 13-1 trigger, and each edge moves it, so
/// each edge sends the SubscribeCOV report, which also carries the changed
/// OUT_OF_SERVICE flag. That holds for a round trip in one
/// WritePropertyMultiple too, where Status_Flags ends where it started. The
/// point runs no intrinsic reporting (no ACCESS_EVENT algorithm;
/// Event_State stays NORMAL), so an edge raises no event notification.
///
/// Active_Authentication_Policy, Number_Of_Authentication_Policies,
/// Authorization_Mode and Priority_For_Writing hold the settings the
/// application's authentication and authorization work from (#1307). A
/// client picks the policy in effect and the authorization mode; the
/// application sets the policy count, the modes it carries out and the
/// door command priority. The module `point_authorization` has the rules.
pub struct AccessPointObject {
    oid: ObjectIdentifier,
    name: String,
    description: String,
    access_event: AccessEvent,
    access_event_tag: u64,
    access_event_time: BACnetTimeStamp,
    access_event_credential: BACnetDeviceObjectReference,
    /// The status the application reports; DISABLED is served instead while
    /// Out_Of_Service is TRUE.
    authentication_status: AuthenticationStatus,
    access_doors: Vec<BACnetDeviceObjectReference>,
    /// The policy, authorization mode and door command priority settings.
    authorization: Authorization,
    event_state: EventState,
    status_flags: StatusFlags,
    out_of_service: bool,
    reliability: Reliability,
    clock: Option<Arc<dyn ClockReader>>,
}

impl AccessPointObject {
    /// Create a new Access Point object.
    pub fn new(instance: u32, name: impl Into<String>) -> Result<Self, Error> {
        let oid = ObjectIdentifier::new(ObjectType::ACCESS_POINT, instance)?;
        Ok(Self {
            oid,
            name: name.into(),
            description: String::new(),
            access_event: AccessEvent::NONE,
            access_event_tag: 0,
            access_event_time: never_updated(),
            access_event_credential: no_credential(),
            authentication_status: AuthenticationStatus::READY,
            access_doors: Vec::new(),
            authorization: Authorization::new(),
            event_state: EventState::NORMAL,
            status_flags: StatusFlags::empty(),
            out_of_service: false,
            reliability: Reliability::NO_FAULT_DETECTED,
            clock: None,
        })
    }

    /// Record the most recent access event: Access_Event, Access_Event_Tag,
    /// Access_Event_Time and Access_Event_Credential, which the
    /// application's access logic produces. They change together, as
    /// Clause 12.31.27.1 has them stored for each event.
    ///
    /// Access_Event_Time is a `BACnetTimeStamp` (Clause 12.31.29) and goes
    /// out in its Clause 21 CHOICE form. A change of it triggers a SubscribeCOV
    /// notification; the other three only ride along (Table 13-1). Over the
    /// network all four stay read-only.
    ///
    /// `credential` names the Access Credential object behind the event.
    /// `None` stores the no-credential reference, instance 4194303, for an
    /// event no credential belongs to or one whose credential is unknown or
    /// kept back (Clause 12.31.30). Given explicitly, that reference carries
    /// 4194303 as the object instance and, when it names a device, as the
    /// device instance too. Refused with VALUE_OUT_OF_RANGE, with none of the
    /// four changing: a reference to another object type, one whose device
    /// identifier isn't a Device (#1285), and one with 4194303 in only one of
    /// the two instances, which is neither a credential nor the
    /// no-credential reference. Access_Event_Credential has no network write
    /// route, so this setter is the only check.
    ///
    /// While Out_Of_Service is TRUE the point performs no authentication or
    /// authorization (Clause 12.31.8), so its access logic has nothing to
    /// report until the return to service; the point leaves that to the
    /// application rather than refusing the call.
    pub fn set_access_event(
        &mut self,
        event: AccessEvent,
        tag: u64,
        time: BACnetTimeStamp,
        credential: Option<BACnetDeviceObjectReference>,
    ) -> Result<(), Error> {
        let credential = credential.unwrap_or_else(no_credential);
        crate::device_reference::check_device_member(credential.device_identifier)?;
        if credential.object_identifier.object_type() != ObjectType::ACCESS_CREDENTIAL {
            return Err(common::value_out_of_range_error());
        }
        let empty = |instance: u32| instance == ObjectIdentifier::MAX_INSTANCE;
        if credential.device_identifier.is_some_and(|device| {
            empty(device.instance_number()) != empty(credential.object_identifier.instance_number())
        }) {
            return Err(common::value_out_of_range_error());
        }
        self.access_event = event;
        self.access_event_tag = tag;
        self.access_event_time = time;
        self.access_event_credential = credential;
        Ok(())
    }

    /// Report the status of the point's authentication process
    /// (Clause 12.31.9), read-only over the network. A value outside the
    /// closed BACnetAuthenticationStatus production is refused with
    /// VALUE_OUT_OF_RANGE. While Out_Of_Service is TRUE the status is kept
    /// but DISABLED is served until the return to service.
    pub fn set_authentication_status(&mut self, status: AuthenticationStatus) -> Result<(), Error> {
        if status.to_raw() > AuthenticationStatus::IN_PROGRESS.to_raw() {
            return Err(common::value_out_of_range_error());
        }
        self.authentication_status = status;
        Ok(())
    }

    /// Authentication_Status as served: DISABLED while Out_Of_Service is
    /// TRUE, else the status last reported.
    pub fn authentication_status(&self) -> AuthenticationStatus {
        if self.out_of_service {
            AuthenticationStatus::DISABLED
        } else {
            self.authentication_status
        }
    }

    /// Set Access_Doors, the Access Door objects whose Present_Value this
    /// point commands once access is granted (Clause 12.31.32). A point that
    /// commands no door keeps the array empty. A reference with no Device
    /// identifier names an object in this device.
    ///
    /// Every reference must name an Access Door object, and a device
    /// identifier, when given, a Device object (#1285); a list breaking
    /// either rule is refused with VALUE_OUT_OF_RANGE and the doors set
    /// before are kept. The array is read-only over the network.
    pub fn set_access_doors(
        &mut self,
        doors: impl IntoIterator<Item = impl Into<BACnetDeviceObjectReference>>,
    ) -> Result<(), Error> {
        let doors: Vec<BACnetDeviceObjectReference> = doors.into_iter().map(Into::into).collect();
        for door in &doors {
            crate::device_reference::check_device_member(door.device_identifier)?;
            if door.object_identifier.object_type() != ObjectType::ACCESS_DOOR {
                return Err(common::value_out_of_range_error());
            }
        }
        self.access_doors = doors;
        Ok(())
    }

    /// Set Number_Of_Authentication_Policies, how many authentication
    /// policies the application defines (Clause 12.31.11), 1 until set. It
    /// is read-only over the network. Zero is refused with
    /// VALUE_OUT_OF_RANGE, and so is a count below
    /// Active_Authentication_Policy: lower the active policy first, with a
    /// write of that property.
    pub fn set_number_of_authentication_policies(&mut self, count: u32) -> Result<(), Error> {
        self.authorization.set_policies(count)
    }

    /// Set the authorization modes the application carries out, the values
    /// a write of Authorization_Mode can take (Clause 12.31.14). A new point
    /// takes AUTHORIZE alone, since the point enforces no mode itself: an
    /// application that acts on Authorization_Mode declares the other modes
    /// it carries out here. The set must hold AUTHORIZE and the mode in
    /// effect, and each mode must be a standard one or a proprietary one from
    /// 64 to 65535; otherwise it is refused with VALUE_OUT_OF_RANGE and the
    /// set before is kept. A repeated mode counts once.
    pub fn set_supported_authorization_modes(
        &mut self,
        modes: impl IntoIterator<Item = AuthorizationMode>,
    ) -> Result<(), Error> {
        self.authorization.set_supported_modes(modes)
    }

    /// Set Priority_For_Writing, the priority at which the application
    /// commands the Access_Doors after a grant (Clauses 12.31.32.1 and
    /// 12.31.33), 16 until set. It is read-only over the network. A
    /// priority outside 1..=16 is refused with VALUE_OUT_OF_RANGE.
    pub fn set_priority_for_writing(&mut self, priority: u8) -> Result<(), Error> {
        self.authorization.set_priority_for_writing(priority)
    }

    /// Record the access event an Out_Of_Service edge raises: a new
    /// transaction, stamped from the Device clock, or with the new tag as a
    /// sequence number when there is no usable clock, and with no credential.
    fn record_out_of_service_event(&mut self, event: AccessEvent) {
        let tag = self.access_event_tag.wrapping_add(1);
        self.access_event = event;
        self.access_event_tag = tag;
        self.access_event_time = update_stamp(self.clock.as_deref(), || tag_sequence(tag));
        self.access_event_credential = no_credential();
    }
}

/// The Access_Event_Credential of an event without a credential
/// (Clause 12.31.30): an Access Credential identifier at instance 4194303,
/// with no device identifier.
fn no_credential() -> BACnetDeviceObjectReference {
    ObjectIdentifier::new(
        ObjectType::ACCESS_CREDENTIAL,
        ObjectIdentifier::MAX_INSTANCE,
    )
    .expect("4194303 is within the instance range")
    .into()
}

/// `tag` as a sequence number in 1..=65535: the tag itself up to 65535, and
/// past that folded back into the range, so consecutive tags, the wrap from
/// the top of the Unsigned range to 0 included, give different numbers.
fn tag_sequence(tag: u64) -> u16 {
    const RANGE: u64 = u16::MAX as u64;
    // In 0..RANGE, so the cast keeps every bit and the sum stays in range.
    (tag.wrapping_sub(1) % RANGE) as u16 + 1
}

impl BACnetObject for AccessPointObject {
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
        if let Some(value) = self.authorization.read(property) {
            return Ok(value);
        }
        match property {
            p if p == PropertyIdentifier::OBJECT_TYPE => {
                Ok(PropertyValue::Enumerated(ObjectType::ACCESS_POINT.to_raw()))
            }
            p if p == PropertyIdentifier::ACCESS_EVENT => {
                Ok(PropertyValue::Enumerated(self.access_event.to_raw()))
            }
            p if p == PropertyIdentifier::ACCESS_EVENT_TAG => {
                Ok(PropertyValue::Unsigned(self.access_event_tag))
            }
            p if p == PropertyIdentifier::ACCESS_EVENT_TIME => {
                timestamp_value(&self.access_event_time)
            }
            p if p == PropertyIdentifier::ACCESS_EVENT_CREDENTIAL => {
                let mut buf = BytesMut::new();
                encode_device_object_reference(&mut buf, &self.access_event_credential);
                Ok(PropertyValue::ApplicationData(buf.to_vec()))
            }
            p if p == PropertyIdentifier::AUTHENTICATION_STATUS => Ok(PropertyValue::Enumerated(
                self.authentication_status().to_raw(),
            )),
            p if p == PropertyIdentifier::ACCESS_DOORS => {
                common::read_array(device_object_references(&self.access_doors), array_index)
            }
            p if p == PropertyIdentifier::EVENT_STATE => {
                Ok(PropertyValue::Enumerated(self.event_state.to_raw()))
            }
            _ => Err(common::unknown_property_error()),
        }
    }

    fn write_property(
        &mut self,
        property: PropertyIdentifier,
        array_index: Option<u32>,
        value: PropertyValue,
        _priority: Option<u8>,
    ) -> Result<(), Error> {
        let was_out_of_service = self.out_of_service;
        if let Some(result) =
            common::write_out_of_service(&mut self.out_of_service, property, &value)
        {
            match (was_out_of_service, self.out_of_service) {
                (false, true) => self.record_out_of_service_event(AccessEvent::OUT_OF_SERVICE),
                (true, false) => {
                    self.record_out_of_service_event(AccessEvent::OUT_OF_SERVICE_RELINQUISHED)
                }
                _ => {}
            }
            return result;
        }
        if let Some(result) = common::write_description(&mut self.description, property, &value) {
            return result;
        }
        if let Some(result) = self.authorization.write(property, array_index, &value) {
            return result;
        }
        Err(crate::common::unhandled_write_error(
            self.property_metadata().as_ref(),
            property,
            array_index,
        ))
    }

    fn property_metadata(&self) -> Cow<'_, [crate::property_metadata::PropertyMetadata]> {
        super::metadata_topology::for_access_point_object(self)
    }

    fn property_list(&self) -> Cow<'static, [PropertyIdentifier]> {
        crate::property_metadata::property_list_from_metadata(self.property_metadata().as_ref())
    }

    /// Table 13-1 lists Access Point, so it takes SubscribeCOV; its report
    /// leads with Access_Event, as the point has no Present_Value.
    fn supports_cov(&self) -> bool {
        true
    }

    fn bind_clock_internal(&mut self, clock: Option<Arc<dyn ClockReader>>) {
        self.clock = clock;
    }
}

// ---------------------------------------------------------------------------
