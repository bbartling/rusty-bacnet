use super::super::*;

#[pymethods]
impl BACnetServer {
    #[new]
    #[pyo3(signature = (
        device_instance,
        device_name="BACnet Device",
        interface="0.0.0.0",
        port=0xBAC0,
        broadcast_address="255.255.255.255",
        transport="bip",
        sc_hub=None,
        sc_vmac=None,
        sc_ca_cert=None,
        sc_client_cert=None,
        sc_client_key=None,
        sc_heartbeat_interval_ms=None,
        sc_heartbeat_timeout_ms=None,
        ipv6_interface=None,
        dcc_password=None,
        reinit_password=None,
        *,
        mutation_policy="permissive",
        dcc_policy="deny_all",
        dcc_source_restriction=None,
        dcc_disable_rate_limit=None,
        serial_port=None,
        mstp_baud=38400,
        mstp_mac=1,
        mstp_max_master=127,
        mstp_max_info_frames=1,
        max_confirmed_in_flight=64,
        max_unconfirmed_in_flight=32,
        max_confirmed_in_flight_per_peer=16,
        max_unconfirmed_in_flight_per_peer=8,
        confirmed_recovery_reserve=4,
        max_recovery_in_flight_per_peer=1,
        rpm_max_result_elements=256,
        rpm_max_service_ack_bytes=16384,
        alarm_summary_max_objects=4096,
        alarm_summary_max_service_ack_bytes=16384,
        enrollment_summary_max_objects=4096,
        enrollment_summary_max_service_ack_bytes=16384,
        atomic_read_file_max_requested_stream_octets=16384,
        atomic_read_file_max_requested_records=256,
        atomic_read_file_max_service_ack_bytes=16384,
        atomic_write_file_max_stream_payload_octets=16384,
        atomic_write_file_max_records=256,
        atomic_write_file_max_record_payload_bytes=16384,
        read_range_max_returned_items=256,
        read_range_max_service_ack_bytes=16384,
        event_information_max_objects=4096,
        event_information_max_returned_summaries=256,
        event_information_max_service_ack_bytes=16384,
        sc_device_uuid=None,
        registered_network_port=None,
        cov_policy=None,
        time_sync_policy=None
    ))]
    fn new(
        device_instance: u32,
        device_name: &str,
        interface: &str,
        port: u16,
        broadcast_address: &str,
        transport: &str,
        sc_hub: Option<String>,
        sc_vmac: Option<Vec<u8>>,
        sc_ca_cert: Option<String>,
        sc_client_cert: Option<String>,
        sc_client_key: Option<String>,
        sc_heartbeat_interval_ms: Option<u64>,
        sc_heartbeat_timeout_ms: Option<u64>,
        ipv6_interface: Option<String>,
        dcc_password: Option<String>,
        reinit_password: Option<String>,
        mutation_policy: &str,
        dcc_policy: &str,
        dcc_source_restriction: Option<Vec<(Option<u16>, Vec<u8>)>>,
        dcc_disable_rate_limit: Option<(u32, u64)>,
        serial_port: Option<String>,
        mstp_baud: u32,
        mstp_mac: u8,
        mstp_max_master: u8,
        mstp_max_info_frames: u8,
        max_confirmed_in_flight: usize,
        max_unconfirmed_in_flight: usize,
        max_confirmed_in_flight_per_peer: usize,
        max_unconfirmed_in_flight_per_peer: usize,
        confirmed_recovery_reserve: usize,
        max_recovery_in_flight_per_peer: usize,
        rpm_max_result_elements: usize,
        rpm_max_service_ack_bytes: usize,
        alarm_summary_max_objects: usize,
        alarm_summary_max_service_ack_bytes: usize,
        enrollment_summary_max_objects: usize,
        enrollment_summary_max_service_ack_bytes: usize,
        atomic_read_file_max_requested_stream_octets: usize,
        atomic_read_file_max_requested_records: usize,
        atomic_read_file_max_service_ack_bytes: usize,
        atomic_write_file_max_stream_payload_octets: usize,
        atomic_write_file_max_records: usize,
        atomic_write_file_max_record_payload_bytes: usize,
        read_range_max_returned_items: usize,
        read_range_max_service_ack_bytes: usize,
        event_information_max_objects: usize,
        event_information_max_returned_summaries: usize,
        event_information_max_service_ack_bytes: usize,
        sc_device_uuid: Option<Vec<u8>>,
        registered_network_port: Option<u32>,
        cov_policy: Option<&Bound<'_, pyo3::types::PyDict>>,
        time_sync_policy: Option<&Bound<'_, pyo3::types::PyDict>>,
    ) -> PyResult<Self> {
        super::constructor_budgets::registered_network_port(registered_network_port, transport)?;
        let mutation_policy = super::constructor_budgets::mutation_policy(mutation_policy)?;
        let super::constructor_budgets::DccConfiguration {
            policy: dcc_policy,
            source_restriction: dcc_source_restriction,
            disable_rate_limit: dcc_disable_rate_limit,
        } = super::constructor_budgets::dcc_configuration(
            dcc_policy,
            &dcc_password,
            dcc_source_restriction,
            dcc_disable_rate_limit,
        )?;
        let super::constructor_budgets::Budgets {
            request_admission_policy,
            read_property_multiple_budget,
            get_alarm_summary_budget,
            get_enrollment_summary_budget,
            atomic_read_file_budget,
            atomic_write_file_budget,
            read_range_budget,
            get_event_information_budget,
        } = super::constructor_budgets::budgets(super::constructor_budgets::BudgetKeywords {
            max_confirmed_in_flight,
            max_unconfirmed_in_flight,
            max_confirmed_in_flight_per_peer,
            max_unconfirmed_in_flight_per_peer,
            confirmed_recovery_reserve,
            max_recovery_in_flight_per_peer,
            rpm_max_result_elements,
            rpm_max_service_ack_bytes,
            alarm_summary_max_objects,
            alarm_summary_max_service_ack_bytes,
            enrollment_summary_max_objects,
            enrollment_summary_max_service_ack_bytes,
            atomic_read_file_max_requested_stream_octets,
            atomic_read_file_max_requested_records,
            atomic_read_file_max_service_ack_bytes,
            atomic_write_file_max_stream_payload_octets,
            atomic_write_file_max_records,
            atomic_write_file_max_record_payload_bytes,
            read_range_max_returned_items,
            read_range_max_service_ack_bytes,
            event_information_max_objects,
            event_information_max_returned_summaries,
            event_information_max_service_ack_bytes,
        })?;
        let cov_policy = super::cov_policy::cov_policy(cov_policy)?;
        let time_sync_policy = super::time_sync_policy::time_sync_policy(time_sync_policy)?;
        if transport == "sc" {
            crate::tls::required_sc_credentials(
                sc_ca_cert.as_deref(),
                sc_client_cert.as_deref(),
                sc_client_key.as_deref(),
            )
            .map_err(|e| pyo3::exceptions::PyValueError::new_err(e.to_string()))?;
        }
        let sc_device_uuid = crate::sc_identity::device_uuid(transport, sc_device_uuid)?;
        Ok(Self {
            inner: Arc::new(Mutex::new(None)),
            device_instance,
            device_name: device_name.to_string(),
            transport_type: transport.to_string(),
            interface: interface.to_string(),
            port,
            broadcast_address: broadcast_address.to_string(),
            registered_network_port,
            sc_hub,
            sc_vmac,
            sc_device_uuid,
            sc_ca_cert,
            sc_client_cert,
            sc_client_key,
            sc_heartbeat_interval_ms,
            sc_heartbeat_timeout_ms,
            ipv6_interface,
            serial_port,
            mstp_baud,
            mstp_mac,
            mstp_max_master,
            mstp_max_info_frames,
            dcc_password,
            mutation_policy,
            dcc_policy,
            dcc_source_restriction,
            dcc_disable_rate_limit,
            reinit_password,
            request_admission_policy,
            read_property_multiple_budget,
            get_alarm_summary_budget,
            get_enrollment_summary_budget,
            atomic_read_file_budget,
            atomic_write_file_budget,
            read_range_budget,
            get_event_information_budget,
            cov_policy,
            time_sync_policy,
            audit_notification_sink: None,
            audit_reporters: None,
            audit_recipient: std::sync::Mutex::new(None),
            device_bindings: std::collections::BTreeMap::new(),
            forwarding_configuration_started: AtomicBool::new(false),
            started: Arc::new(AtomicBool::new(false)),
            pending_objects: std::sync::Mutex::new(Vec::new()),
            pending_forwarder_save_counters: std::sync::Mutex::new(Vec::new()),
            forwarder_save_counters: Arc::new(std::sync::Mutex::new(Vec::new())),
        })
    }

    /// Test seam for verifying that fallible startup leaves registrations intact.
    #[doc(hidden)]
    fn _pending_registration_count(&self) -> PyResult<usize> {
        Ok(self.lock_pending()?.len())
    }

    /// Add an Analog Input object to the server (before starting).
    #[pyo3(signature = (instance, name, units=62, present_value=0.0))]
    fn add_analog_input(
        &self,
        instance: u32,
        name: &str,
        units: u32,
        present_value: f32,
    ) -> PyResult<()> {
        let mut ai = AnalogInputObject::new(instance, name, units).map_err(to_py_err)?;
        ai.set_present_value(present_value);
        self.push_pending(Box::new(ai))
    }

    /// Add an Analog Output object to the server (before starting).
    #[pyo3(signature = (instance, name, units=62))]
    fn add_analog_output(&self, instance: u32, name: &str, units: u32) -> PyResult<()> {
        let ao = AnalogOutputObject::new(instance, name, units).map_err(to_py_err)?;
        self.push_pending(Box::new(ao))
    }

    /// Add a Binary Input object to the server (before starting).
    #[pyo3(signature = (instance, name))]
    fn add_binary_input(&self, instance: u32, name: &str) -> PyResult<()> {
        let bi = BinaryInputObject::new(instance, name).map_err(to_py_err)?;
        self.push_pending(Box::new(bi))
    }

    /// Add a Binary Output object to the server (before starting).
    #[pyo3(signature = (instance, name))]
    fn add_binary_output(&self, instance: u32, name: &str) -> PyResult<()> {
        let bo = BinaryOutputObject::new(instance, name).map_err(to_py_err)?;
        self.push_pending(Box::new(bo))
    }

    /// Add a Multi-State Input object to the server (before starting).
    #[pyo3(signature = (instance, name, number_of_states))]
    fn add_multistate_input(
        &self,
        instance: u32,
        name: &str,
        number_of_states: u32,
    ) -> PyResult<()> {
        let msi =
            MultiStateInputObject::new(instance, name, number_of_states).map_err(to_py_err)?;
        self.push_pending(Box::new(msi))
    }

    /// Add a Multi-State Output object to the server (before starting).
    #[pyo3(signature = (instance, name, number_of_states))]
    fn add_multistate_output(
        &self,
        instance: u32,
        name: &str,
        number_of_states: u32,
    ) -> PyResult<()> {
        let mso =
            MultiStateOutputObject::new(instance, name, number_of_states).map_err(to_py_err)?;
        self.push_pending(Box::new(mso))
    }

    /// Add a Multi-State Value object to the server (before starting).
    #[pyo3(signature = (instance, name, number_of_states))]
    fn add_multistate_value(
        &self,
        instance: u32,
        name: &str,
        number_of_states: u32,
    ) -> PyResult<()> {
        let msv =
            MultiStateValueObject::new(instance, name, number_of_states).map_err(to_py_err)?;
        self.push_pending(Box::new(msv))
    }

    /// Add a Calendar object to the server (before starting).
    #[pyo3(signature = (instance, name))]
    fn add_calendar(&self, instance: u32, name: &str) -> PyResult<()> {
        let cal = CalendarObject::new(instance, name).map_err(to_py_err)?;
        self.push_pending(Box::new(cal))
    }

    /// Add a Schedule object to the server (before starting).
    #[pyo3(signature = (instance, name))]
    fn add_schedule(&self, instance: u32, name: &str) -> PyResult<()> {
        let sched = ScheduleObject::new(instance, name, PropertyValue::Null).map_err(to_py_err)?;
        self.push_pending(Box::new(sched))
    }

    /// Add a Notification Class object to the server (before starting).
    ///
    /// With `storage_path`, a Recipient_List a client writes is kept in that
    /// file and restored when the server is built again. A write whose list
    /// cannot be saved is refused with DEVICE / OPERATIONAL_PROBLEM, and the
    /// old list stays. Without it the list lives in memory only. Give each
    /// class its own file: one that holds another object's list, or that
    /// this backend did not write, raises BacnetError here.
    #[pyo3(signature = (instance, name, notification_class=0, storage_path=None))]
    fn add_notification_class(
        &self,
        instance: u32,
        name: &str,
        notification_class: u32,
        storage_path: Option<&str>,
    ) -> PyResult<()> {
        let mut nc = match storage_path {
            Some(path) => {
                let storage =
                    Arc::new(FileNotificationClassPersistence::new(path).map_err(to_py_err)?);
                NotificationClass::with_persistence(instance, name, storage).map_err(to_py_err)?
            }
            None => NotificationClass::new(instance, name).map_err(to_py_err)?,
        };
        nc.notification_class = notification_class;
        self.push_pending(Box::new(nc))
    }

    /// Add a Trend Log object to the server (before starting).
    #[pyo3(signature = (instance, name, buffer_size=100))]
    fn add_trend_log(&self, instance: u32, name: &str, buffer_size: u32) -> PyResult<()> {
        let tl = TrendLogObject::new(instance, name, buffer_size).map_err(to_py_err)?;
        self.push_pending(Box::new(tl))
    }

    /// Add an Audit Log object to the server (before starting).
    #[pyo3(signature = (instance, name, storage_path, buffer_size=100))]
    fn add_audit_log(
        &self,
        instance: u32,
        name: &str,
        storage_path: &str,
        buffer_size: u32,
    ) -> PyResult<()> {
        let storage = Arc::new(FileAuditLogPersistence::new(storage_path).map_err(to_py_err)?);
        let al = AuditLogObject::new(instance, name, buffer_size, storage).map_err(to_py_err)?;
        self.push_pending(Box::new(al))
    }

    /// Add an Audit Reporter object to the server (before starting).
    #[pyo3(signature = (instance, name))]
    fn add_audit_reporter(&self, instance: u32, name: &str) -> PyResult<()> {
        let ar = AuditReporterObject::new(instance, name).map_err(to_py_err)?;
        self.push_pending(Box::new(ar))
    }

    // -----------------------------------------------------------------------
    // Pattern A: new(instance, name) — simple two-param constructors
    // -----------------------------------------------------------------------

    /// Add a Command object to the server (before starting).
    ///
    /// `action` is the Action array: one list of `ActionCommand` mappings per
    /// element, so writing N to Present_Value runs list N. `action_text`
    /// serves Action_Text and needs one text per list. Shapes and Python
    /// types are checked here (TypeError / ValueError); the object's own
    /// setters refuse what BACnet doesn't allow, such as a priority outside
    /// 1 to 16 or a text count that differs from the list count, as a
    /// protocol error (VALUE_OUT_OF_RANGE).
    #[pyo3(signature = (instance, name, *, action=None, action_text=None))]
    fn add_command(
        &self,
        instance: u32,
        name: &str,
        action: Option<Bound<'_, PyAny>>,
        action_text: Option<Vec<String>>,
    ) -> PyResult<()> {
        let action = action
            .map(|action| crate::types::action_lists_from_py(&action))
            .transpose()?;
        let obj = command(instance, name, action, action_text).map_err(to_py_err)?;
        self.push_pending(Box::new(obj))
    }

    /// Add a Timer object to the server (before starting).
    #[pyo3(signature = (instance, name))]
    fn add_timer(&self, instance: u32, name: &str) -> PyResult<()> {
        let obj = TimerObject::new(instance, name).map_err(to_py_err)?;
        self.push_pending(Box::new(obj))
    }

    /// Add a Load Control object to the server (before starting).
    #[pyo3(signature = (instance, name))]
    fn add_load_control(&self, instance: u32, name: &str) -> PyResult<()> {
        let obj = LoadControlObject::new(instance, name).map_err(to_py_err)?;
        self.push_pending(Box::new(obj))
    }

    /// Add a Program object to the server (before starting).
    #[pyo3(signature = (instance, name))]
    fn add_program(&self, instance: u32, name: &str) -> PyResult<()> {
        let obj = ProgramObject::new(instance, name).map_err(to_py_err)?;
        self.push_pending(Box::new(obj))
    }

    /// Add a Lighting Output object to the server (before starting).
    #[pyo3(signature = (instance, name))]
    fn add_lighting_output(&self, instance: u32, name: &str) -> PyResult<()> {
        let obj = LightingOutputObject::new(instance, name).map_err(to_py_err)?;
        self.push_pending(Box::new(obj))
    }

    /// Add a Binary Lighting Output object to the server (before starting).
    #[pyo3(signature = (instance, name))]
    fn add_binary_lighting_output(&self, instance: u32, name: &str) -> PyResult<()> {
        let obj = BinaryLightingOutputObject::new(instance, name).map_err(to_py_err)?;
        self.push_pending(Box::new(obj))
    }

    /// Add a Life Safety Point object to the server (before starting).
    #[pyo3(signature = (instance, name))]
    fn add_life_safety_point(&self, instance: u32, name: &str) -> PyResult<()> {
        let obj = LifeSafetyPointObject::new(instance, name).map_err(to_py_err)?;
        self.push_pending(Box::new(obj))
    }

    /// Add a Life Safety Zone object to the server (before starting).
    #[pyo3(signature = (instance, name))]
    fn add_life_safety_zone(&self, instance: u32, name: &str) -> PyResult<()> {
        let obj = LifeSafetyZoneObject::new(instance, name).map_err(to_py_err)?;
        self.push_pending(Box::new(obj))
    }

    /// Add a Group object to the server (before starting); its Present_Value
    /// is rebuilt from `members` on each read, one result per member, in
    /// order.
    ///
    /// `members` takes the `read_property_multiple` spec shape, checked as
    /// the endpoint owners' `add_group` checks it: a member listing no
    /// properties, a property identifier past 22 bits, or a group's
    /// Present_Value is a ValueError naming its position and the rule.
    #[pyo3(signature = (instance, name, members=None))]
    fn add_group(
        &self,
        instance: u32,
        name: &str,
        members: Option<Vec<crate::types::PyReadAccessSpec>>,
    ) -> PyResult<()> {
        let members = crate::group_members::members(members);
        let obj = crate::group_members::group(instance, name, &members)?;
        self.push_pending(Box::new(obj))
    }

    /// Add a Global Group object to the server (before starting).
    #[pyo3(signature = (instance, name))]
    fn add_global_group(&self, instance: u32, name: &str) -> PyResult<()> {
        let obj = GlobalGroupObject::new(instance, name).map_err(to_py_err)?;
        self.push_pending(Box::new(obj))
    }

    /// Add a Structured View object to the server (before starting).
    #[pyo3(signature = (instance, name))]
    fn add_structured_view(&self, instance: u32, name: &str) -> PyResult<()> {
        let obj = StructuredViewObject::new(instance, name).map_err(to_py_err)?;
        self.push_pending(Box::new(obj))
    }

    /// Add an Alert Enrollment object to the server (before starting).
    #[pyo3(signature = (instance, name, initial_source))]
    fn add_alert_enrollment(
        &self,
        instance: u32,
        name: &str,
        initial_source: PyObjectIdentifier,
    ) -> PyResult<()> {
        let obj = AlertEnrollmentObject::new(instance, name, initial_source.to_rust())
            .map_err(to_py_err)?;
        self.push_pending(Box::new(obj))
    }

    /// Add an Access Credential object to the server (before starting).
    #[pyo3(signature = (instance, name))]
    fn add_access_credential(&self, instance: u32, name: &str) -> PyResult<()> {
        let obj = AccessCredentialObject::new(instance, name).map_err(to_py_err)?;
        self.push_pending(Box::new(obj))
    }

    /// Add an Access User object to the server (before starting).
    #[pyo3(signature = (instance, name))]
    fn add_access_user(&self, instance: u32, name: &str) -> PyResult<()> {
        let obj = AccessUserObject::new(instance, name).map_err(to_py_err)?;
        self.push_pending(Box::new(obj))
    }

    /// Add an Access Zone object to the server (before starting).
    #[pyo3(signature = (instance, name))]
    fn add_access_zone(&self, instance: u32, name: &str) -> PyResult<()> {
        let obj = AccessZoneObject::new(instance, name).map_err(to_py_err)?;
        self.push_pending(Box::new(obj))
    }

    /// Add an Elevator Group object to the server (before starting).
    ///
    /// `machine_room_id` names the Positive Integer Value object served as
    /// Machine_Room_ID. Any other object type raises a protocol error
    /// (VALUE_OUT_OF_RANGE). Omit it to keep the "no room number" default.
    #[pyo3(signature = (instance, name, machine_room_id=None))]
    fn add_elevator_group(
        &self,
        instance: u32,
        name: &str,
        machine_room_id: Option<PyObjectIdentifier>,
    ) -> PyResult<()> {
        let obj = elevator_group(instance, name, machine_room_id.map(|oid| oid.to_rust()))
            .map_err(to_py_err)?;
        self.push_pending(Box::new(obj))
    }

    /// Add an Escalator object to the server (before starting).
    #[pyo3(signature = (instance, name))]
    fn add_escalator(&self, instance: u32, name: &str) -> PyResult<()> {
        let obj = EscalatorObject::new(instance, name).map_err(to_py_err)?;
        self.push_pending(Box::new(obj))
    }

    // -----------------------------------------------------------------------
    // Value types — all take new(instance, name)
    // -----------------------------------------------------------------------

    /// Add an Integer Value object to the server (before starting).
    #[pyo3(signature = (instance, name))]
    fn add_integer_value(&self, instance: u32, name: &str) -> PyResult<()> {
        let obj = IntegerValueObject::new(instance, name).map_err(to_py_err)?;
        self.push_pending(Box::new(obj))
    }

    /// Add a Positive Integer Value object to the server (before starting).
    #[pyo3(signature = (instance, name))]
    fn add_positive_integer_value(&self, instance: u32, name: &str) -> PyResult<()> {
        let obj = PositiveIntegerValueObject::new(instance, name).map_err(to_py_err)?;
        self.push_pending(Box::new(obj))
    }

    /// Add a Large Analog Value object to the server (before starting).
    #[pyo3(signature = (instance, name))]
    fn add_large_analog_value(&self, instance: u32, name: &str) -> PyResult<()> {
        let obj = LargeAnalogValueObject::new(instance, name).map_err(to_py_err)?;
        self.push_pending(Box::new(obj))
    }

    /// Add a Character String Value object to the server (before starting).
    #[pyo3(signature = (instance, name))]
    fn add_character_string_value(&self, instance: u32, name: &str) -> PyResult<()> {
        let obj = CharacterStringValueObject::new(instance, name).map_err(to_py_err)?;
        self.push_pending(Box::new(obj))
    }

    /// Add an Octet String Value object to the server (before starting).
    #[pyo3(signature = (instance, name))]
    fn add_octet_string_value(&self, instance: u32, name: &str) -> PyResult<()> {
        let obj = OctetStringValueObject::new(instance, name).map_err(to_py_err)?;
        self.push_pending(Box::new(obj))
    }

    /// Add a Bit String Value object to the server (before starting).
    #[pyo3(signature = (instance, name))]
    fn add_bit_string_value(&self, instance: u32, name: &str) -> PyResult<()> {
        let obj = BitStringValueObject::new(instance, name).map_err(to_py_err)?;
        self.push_pending(Box::new(obj))
    }

    /// Add a Date Value object to the server (before starting).
    #[pyo3(signature = (instance, name))]
    fn add_date_value(&self, instance: u32, name: &str) -> PyResult<()> {
        let obj = DateValueObject::new(instance, name).map_err(to_py_err)?;
        self.push_pending(Box::new(obj))
    }

    /// Add a Time Value object to the server (before starting).
    #[pyo3(signature = (instance, name))]
    fn add_time_value(&self, instance: u32, name: &str) -> PyResult<()> {
        let obj = TimeValueObject::new(instance, name).map_err(to_py_err)?;
        self.push_pending(Box::new(obj))
    }

    /// Add a DateTime Value object to the server (before starting).
    #[pyo3(signature = (instance, name))]
    fn add_date_time_value(&self, instance: u32, name: &str) -> PyResult<()> {
        let obj = DateTimeValueObject::new(instance, name).map_err(to_py_err)?;
        self.push_pending(Box::new(obj))
    }

    /// Add a Date Pattern Value object to the server (before starting).
    #[pyo3(signature = (instance, name))]
    fn add_date_pattern_value(&self, instance: u32, name: &str) -> PyResult<()> {
        let obj = DatePatternValueObject::new(instance, name).map_err(to_py_err)?;
        self.push_pending(Box::new(obj))
    }

    /// Add a Time Pattern Value object to the server (before starting).
    #[pyo3(signature = (instance, name))]
    fn add_time_pattern_value(&self, instance: u32, name: &str) -> PyResult<()> {
        let obj = TimePatternValueObject::new(instance, name).map_err(to_py_err)?;
        self.push_pending(Box::new(obj))
    }

    /// Add a DateTime Pattern Value object to the server (before starting).
    #[pyo3(signature = (instance, name))]
    fn add_date_time_pattern_value(&self, instance: u32, name: &str) -> PyResult<()> {
        let obj = DateTimePatternValueObject::new(instance, name).map_err(to_py_err)?;
        self.push_pending(Box::new(obj))
    }

    // -----------------------------------------------------------------------
    // Pattern B: new(instance, name, extra_param) — three-param constructors
    // -----------------------------------------------------------------------

    /// Add an Accumulator object to the server (before starting).
    #[pyo3(signature = (instance, name, units=62))]
    fn add_accumulator(&self, instance: u32, name: &str, units: u32) -> PyResult<()> {
        let obj = AccumulatorObject::new(instance, name, units).map_err(to_py_err)?;
        self.push_pending(Box::new(obj))
    }

    /// Add a Pulse Converter object to the server (before starting).
    #[pyo3(signature = (instance, name, units=62))]
    fn add_pulse_converter(&self, instance: u32, name: &str, units: u32) -> PyResult<()> {
        let obj = PulseConverterObject::new(instance, name, units).map_err(to_py_err)?;
        self.push_pending(Box::new(obj))
    }

    /// Add a File object to the server (before starting).
    #[pyo3(signature = (instance, name, file_type="application/octet-stream"))]
    fn add_file(&self, instance: u32, name: &str, file_type: &str) -> PyResult<()> {
        let obj = FileObject::new(instance, name, file_type).map_err(to_py_err)?;
        self.push_pending(Box::new(obj))
    }

    /// Add an Event Enrollment object to the server (before starting).
    ///
    /// `event_type` defaults to `EventType.CHANGE_OF_BITSTRING`.
    #[pyo3(signature = (
        instance,
        name,
        event_type=PyEventType { inner: EventType::CHANGE_OF_BITSTRING }
    ))]
    fn add_event_enrollment(
        &self,
        instance: u32,
        name: &str,
        event_type: PyEventType,
    ) -> PyResult<()> {
        let obj =
            EventEnrollmentObject::new(instance, name, event_type.to_rust()).map_err(to_py_err)?;
        self.push_pending(Box::new(obj))
    }

    /// Add an explicitly configured local-target Staging object before starting.
    #[pyo3(signature = (
        instance,
        name,
        present_value,
        min_present_value,
        units,
        priority_for_writing,
        stages,
        target_references,
        stage_names=None
    ))]
    fn add_staging(
        &self,
        instance: u32,
        name: &str,
        present_value: f32,
        min_present_value: f32,
        units: u32,
        priority_for_writing: u8,
        stages: Vec<(f32, Vec<bool>, f32)>,
        target_references: Vec<PyObjectIdentifier>,
        stage_names: Option<Vec<String>>,
    ) -> PyResult<()> {
        let config = staging_config(
            present_value,
            min_present_value,
            units,
            priority_for_writing,
            stages,
            target_references,
            stage_names,
        );
        let obj = StagingObject::new(instance, name, config).map_err(to_py_err)?;
        self.push_pending(Box::new(obj))
    }

    /// Add a Lift object to the server (before starting).
    #[pyo3(signature = (instance, name, num_floors))]
    fn add_lift(&self, instance: u32, name: &str, num_floors: usize) -> PyResult<()> {
        let obj = LiftObject::new(instance, name, num_floors).map_err(to_py_err)?;
        self.push_pending(Box::new(obj))
    }

    /// Add an Event Log object to the server (before starting).
    #[pyo3(signature = (instance, name, buffer_size=100))]
    fn add_event_log(&self, instance: u32, name: &str, buffer_size: u32) -> PyResult<()> {
        let obj = EventLogObject::new(instance, name, buffer_size).map_err(to_py_err)?;
        self.push_pending(Box::new(obj))
    }

    /// Add a Trend Log Multiple object to the server (before starting).
    #[pyo3(signature = (instance, name, buffer_size=100))]
    fn add_trend_log_multiple(&self, instance: u32, name: &str, buffer_size: u32) -> PyResult<()> {
        let obj = TrendLogMultipleObject::new(instance, name, buffer_size).map_err(to_py_err)?;
        self.push_pending(Box::new(obj))
    }
}

fn staging_config(
    present_value: f32,
    min_present_value: f32,
    units: u32,
    priority_for_writing: u8,
    stages: Vec<(f32, Vec<bool>, f32)>,
    target_references: Vec<PyObjectIdentifier>,
    stage_names: Option<Vec<String>>,
) -> StagingConfig {
    StagingConfig {
        present_value,
        min_present_value,
        units,
        priority_for_writing,
        stages: stages
            .into_iter()
            .map(|(limit, values, deadband)| BACnetStageLimitValue {
                limit,
                values,
                deadband,
            })
            .collect(),
        target_references: target_references
            .into_iter()
            .map(|reference| BACnetDeviceObjectReference {
                device_identifier: None,
                object_identifier: reference.to_rust(),
            })
            .collect(),
        stage_names,
    }
}

/// Build an Elevator Group, applying the optional Machine_Room_ID through the
/// object's own validating setter.
fn elevator_group(
    instance: u32,
    name: &str,
    machine_room_id: Option<bacnet_types::primitives::ObjectIdentifier>,
) -> Result<ElevatorGroupObject, bacnet_types::error::Error> {
    let mut obj = ElevatorGroupObject::new(instance, name)?;
    if let Some(oid) = machine_room_id {
        obj.set_machine_room_id(oid)?;
    }
    Ok(obj)
}

/// Build a Command, applying the optional Action lists and Action_Text through
/// the object's own validating setters, Action first.
fn command(
    instance: u32,
    name: &str,
    action: Option<Vec<bacnet_types::constructed::BACnetActionList>>,
    action_text: Option<Vec<String>>,
) -> Result<CommandObject, bacnet_types::error::Error> {
    let mut obj = CommandObject::new(instance, name)?;
    if let Some(action) = action {
        obj.set_action(action)?;
    }
    if let Some(texts) = action_text {
        obj.set_action_text(texts)?;
    }
    Ok(obj)
}

#[cfg(test)]
#[path = "registration_tests.rs"]
mod tests;
