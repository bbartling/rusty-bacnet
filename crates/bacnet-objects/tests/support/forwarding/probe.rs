//! An object that answers every `BACnetObject` method itself, none the way
//! the trait default would, and logs each call it receives with its
//! arguments.

use std::borrow::Cow;
use std::fmt::Debug;
use std::sync::{Arc, LazyLock, Mutex};
use std::time::Duration;

use bacnet_objects::analog::AnalogValueObject;
use bacnet_objects::audit::{
    AuditLogForwarding, AuditLogNotificationSink, AuditLogObject, AuditLogPersistence,
    AuditLogSnapshot, AuditLogStorage, AuditPolicyAuthority, AuditReporterAuthority,
    AuditReporterObject, AuditSendDelay, ObjectAuditPolicy,
};
use bacnet_objects::clock::{ClockFrame, ClockReader};
use bacnet_objects::command::{CommandRun, RunPlan};
use bacnet_objects::command_source::CommandOrigin;
use bacnet_objects::device::{DeviceAuthority, DeviceConfig, DeviceObject};
use bacnet_objects::event::{
    EnrollmentSummaryCapability, EventStateChange, EventTransitionCommit,
    EventTransitionCommitError, TransitionOutcome,
};
use bacnet_objects::event_enrollment::{
    EventEnrollmentEvalState, EventEnrollmentMonitoredSource, EventEnrollmentReliabilityCommit,
};
use bacnet_objects::file::{FileConfiguration, FileObject, FileStorage};
use bacnet_objects::log_buffer::{LogBufferRecords, LogRecordIdentity};
use bacnet_objects::property_metadata::{
    PropertyConformance, PropertyMetadata, PropertyWriteCapability,
};
use bacnet_objects::schedule::{ScheduleTargetOutcome, ScheduleWrite};
use bacnet_objects::staging::StagingWritePlan;
use bacnet_objects::traits::{
    BACnetObject, CovReportedProperty, LifeSafetyOperationEffect, LifeSafetyOperationOutcome,
    MonotonicClock, ReliabilityEvaluation,
};
use bacnet_objects::trend::TrendLogObject;
use bacnet_types::bitstring::{AuditOperationFlags, BACnetPriorityFilter, EventTransitionBits};
use bacnet_types::calendar::SpecificDate;
use bacnet_types::constructed::{
    BACnetDeviceObjectReference, BACnetEventLogRecord, BACnetLogMultipleRecord, BACnetLogRecord,
    BACnetObjectPropertyReference, BACnetObjectSelector,
};
use bacnet_types::enums::{
    AuditLevel, ErrorClass, ErrorCode, EventState, EventType, LifeSafetyOperation, ObjectType,
    PropertyIdentifier as P, Reliability,
};
use bacnet_types::error::Error;
use bacnet_types::primitives::{BACnetTimeStamp, Date, ObjectIdentifier, PropertyValue, Time};

pub const CUSTOM: P = P::from_raw(5000);
pub const CUSTOM_LIST: P = P::from_raw(5001);
const REPORTED: [CovReportedProperty; 1] = [CovReportedProperty::Trigger(CUSTOM)];
/// DESCRIPTION is writable here, and CUSTOM is absent, unlike the probe's
/// own answers, so defaults derived from these rows give themselves away.
const METADATA: [PropertyMetadata; 5] = [
    PropertyMetadata::new(
        P::OBJECT_IDENTIFIER,
        PropertyConformance::RequiredRead,
        None,
        PropertyWriteCapability::ReadOnly,
    ),
    PropertyMetadata::new(
        P::OBJECT_NAME,
        PropertyConformance::RequiredRead,
        None,
        PropertyWriteCapability::ReadOnly,
    ),
    PropertyMetadata::new(
        P::OBJECT_TYPE,
        PropertyConformance::RequiredRead,
        None,
        PropertyWriteCapability::ReadOnly,
    ),
    PropertyMetadata::new(
        P::DESCRIPTION,
        PropertyConformance::Optional,
        None,
        PropertyWriteCapability::Always,
    ),
    PropertyMetadata::new(
        P::PROPERTY_LIST,
        PropertyConformance::RequiredRead,
        None,
        PropertyWriteCapability::ReadOnly,
    ),
];

/// The calls a probe received, oldest first, each as `name(arguments)`.
pub type CallLog = Arc<Mutex<Vec<String>>>;

/// Empty the log, returning what it held.
pub fn take(log: &CallLog) -> Vec<String> {
    std::mem::take(&mut *log.lock().unwrap())
}

/// The day the probe's calendar is active, and the day schedule rows pass.
pub fn day() -> SpecificDate {
    SpecificDate::new(2026, 10, 2).unwrap()
}

pub fn noon() -> Time {
    Time {
        hour: 12,
        minute: 0,
        second: 0,
        hundredths: 0,
    }
}

pub fn oid(object_type: ObjectType, instance: u32) -> ObjectIdentifier {
    ObjectIdentifier::new(object_type, instance).unwrap()
}

pub fn property_error(code: ErrorCode) -> Error {
    Error::Protocol {
        class: ErrorClass::PROPERTY.to_raw() as u32,
        code: code.to_raw() as u32,
    }
}

struct NoClock;

impl ClockReader for NoClock {
    fn read_clock(&self) -> Option<ClockFrame> {
        None
    }
}

// One instance of each clock, so a row passes the same handle to the probe
// and to an adapter, and the log can name it by address.
static CLOCK: LazyLock<Arc<dyn ClockReader>> = LazyLock::new(|| Arc::new(NoClock));
static MONOTONIC: LazyLock<Arc<MonotonicClock>> =
    LazyLock::new(|| Arc::new(|| Duration::from_secs(99)));

pub fn clock() -> Arc<dyn ClockReader> {
    CLOCK.clone()
}

pub fn monotonic() -> Arc<MonotonicClock> {
    MONOTONIC.clone()
}

/// A capability or handle, rendered as the address it points at.
pub fn address<T: ?Sized>(reference: &T) -> String {
    format!("{:p}", std::ptr::from_ref(reference).cast::<()>())
}

pub fn schedule_write(value: u64) -> ScheduleWrite {
    ScheduleWrite {
        value: PropertyValue::Unsigned(value),
        priority: 16,
        references: Vec::new(),
    }
}

struct NoPersistence;

impl AuditLogPersistence for NoPersistence {
    fn load(&self, _: ObjectIdentifier) -> Result<Option<AuditLogSnapshot>, Error> {
        Ok(None)
    }
    fn commit(&self, _: &AuditLogSnapshot) -> Result<(), Error> {
        Ok(())
    }
}

/// Answers every method of the trait, none the way its default would. The
/// capability hooks lend out objects the probe owns, so an adapter has to
/// hand out the probe's own and not a copy.
pub struct Probe {
    oid: ObjectIdentifier,
    log: CallLog,
    device: DeviceObject,
    value: AnalogValueObject,
    reporter: AuditReporterObject,
    audit_log: AuditLogObject,
    file: FileObject,
    trend_log: TrendLogObject,
}

impl Probe {
    pub fn new(object_type: ObjectType, log: CallLog) -> Self {
        let mut audit_log =
            AuditLogObject::new(3, "Probe log", 4, Arc::new(NoPersistence)).unwrap();
        audit_log.set_member_of(Some(BACnetDeviceObjectReference {
            device_identifier: None,
            object_identifier: oid(ObjectType::AUDIT_LOG, 9),
        }));
        let mut value = AnalogValueObject::new(7, "Probe value", 62).unwrap();
        value.set_audit_policy(ObjectAuditPolicy {
            level: Some(AuditLevel::NONE),
            ..ObjectAuditPolicy::default()
        });
        Self {
            oid: oid(object_type, 1),
            log,
            device: DeviceObject::new(DeviceConfig {
                instance: 77,
                ..DeviceConfig::default()
            })
            .unwrap(),
            value,
            reporter: AuditReporterObject::new(17, "Probe reporter").unwrap(),
            audit_log,
            file: FileObject::new(5, "Probe file", "test").unwrap(),
            trend_log: TrendLogObject::new(6, "Probe trend", 4).unwrap(),
        }
    }

    /// Log one call: `arguments` is a tuple, `()` for none.
    fn called(&self, method: &str, arguments: impl Debug) {
        self.log
            .lock()
            .unwrap()
            .push(format!("{method}{arguments:?}"));
    }
}

impl BACnetObject for Probe {
    fn device_authority_internal(&mut self) -> Option<DeviceAuthority<'_>> {
        self.called("device_authority_internal", ());
        self.device.device_authority_internal()
    }
    fn audit_object_policy_internal(&self) -> ObjectAuditPolicy {
        self.called("audit_object_policy_internal", ());
        ObjectAuditPolicy {
            level: Some(AuditLevel::AUDIT_ALL),
            ..ObjectAuditPolicy::default()
        }
    }
    fn audit_policy_authority_internal(&mut self) -> Option<AuditPolicyAuthority<'_>> {
        self.called("audit_policy_authority_internal", ());
        self.value.audit_policy_authority_internal()
    }
    fn audit_reporter_internal(&self) -> Option<&AuditReporterObject> {
        self.called("audit_reporter_internal", ());
        Some(&self.reporter)
    }
    fn audit_reporter_authority_internal(&mut self) -> Option<AuditReporterAuthority<'_>> {
        self.called("audit_reporter_authority_internal", ());
        self.reporter.audit_reporter_authority_internal()
    }
    fn configure_audit_reporter_internal(
        &mut self,
        level: AuditLevel,
        operations: AuditOperationFlags,
        confirmed: bool,
        selectors: Option<Vec<BACnetObjectSelector>>,
        priorities: BACnetPriorityFilter,
        maximum_send_delay: Option<AuditSendDelay>,
    ) -> Result<(), Error> {
        let arguments = (
            level,
            operations,
            confirmed,
            selectors,
            priorities,
            maximum_send_delay,
        );
        self.called("configure_audit_reporter_internal", arguments);
        Ok(())
    }
    fn object_identifier(&self) -> ObjectIdentifier {
        self.called("object_identifier", ());
        self.oid
    }
    fn object_name(&self) -> &str {
        self.called("object_name", ());
        "Probe"
    }
    fn read_property(&self, property: P, index: Option<u32>) -> Result<PropertyValue, Error> {
        self.called("read_property", (property, index));
        if property == CUSTOM {
            Ok(PropertyValue::Unsigned(7))
        } else {
            Err(property_error(ErrorCode::UNKNOWN_PROPERTY))
        }
    }
    fn write_property(
        &mut self,
        property: P,
        index: Option<u32>,
        value: PropertyValue,
        priority: Option<u8>,
    ) -> Result<(), Error> {
        self.called("write_property", (property, index, value, priority));
        Ok(())
    }
    fn write_property_from(
        &mut self,
        property: P,
        index: Option<u32>,
        value: PropertyValue,
        priority: Option<u8>,
        origin: &CommandOrigin,
    ) -> Result<(), Error> {
        let arguments = (property, index, value, priority, origin);
        self.called("write_property_from", arguments);
        // Unlike the default, which answers as `write_property` does.
        Err(property_error(ErrorCode::VALUE_OUT_OF_RANGE))
    }
    fn property_metadata(&self) -> Cow<'_, [PropertyMetadata]> {
        self.called("property_metadata", ());
        Cow::Borrowed(&METADATA)
    }
    fn property_list(&self) -> Cow<'static, [P]> {
        self.called("property_list", ());
        Cow::Borrowed(&[P::OBJECT_IDENTIFIER, P::OBJECT_NAME, P::OBJECT_TYPE, CUSTOM])
    }
    fn bind_clock_internal(&mut self, clock: Option<Arc<dyn ClockReader>>) {
        let clock = clock.as_deref().map(address);
        self.called("bind_clock_internal", (clock,));
    }
    fn advance_time_internal(&mut self, elapsed: Duration) -> bool {
        self.called("advance_time_internal", (elapsed,));
        true
    }
    fn bind_monotonic_clock_internal(&mut self, clock: Option<Arc<MonotonicClock>>) {
        let clock = clock.as_deref().map(address);
        self.called("bind_monotonic_clock_internal", (clock,));
    }
    fn advance_monotonic_time_internal(&mut self, now: Duration) -> bool {
        self.called("advance_monotonic_time_internal", (now,));
        true
    }
    fn next_monotonic_deadline_internal(&self) -> Option<Duration> {
        self.called("next_monotonic_deadline_internal", ());
        Some(Duration::from_secs(99))
    }
    fn cov_snapshot_internal(&self) -> Option<Box<dyn BACnetObject>> {
        self.called("cov_snapshot_internal", ());
        Some(Box::new(
            AuditReporterObject::new(18, "Probe snapshot").unwrap(),
        ))
    }
    fn binary_lighting_blink_count_internal(&self) -> u64 {
        self.called("binary_lighting_blink_count_internal", ());
        123
    }
    fn is_writable_property(&self, property: P) -> bool {
        self.called("is_writable_property", (property,));
        property == CUSTOM
    }
    fn is_array_property(&self, property: P) -> bool {
        self.called("is_array_property", (property,));
        property == CUSTOM
    }
    fn is_list_property(&self, property: P) -> bool {
        self.called("is_list_property", (property,));
        property == CUSTOM_LIST
    }
    fn is_createable(&self) -> bool {
        self.called("is_createable", ());
        true
    }
    fn is_deleteable(&self) -> bool {
        self.called("is_deleteable", ());
        false
    }
    fn required_properties(&self) -> Cow<'static, [P]> {
        self.called("required_properties", ());
        Cow::Borrowed(&[CUSTOM])
    }
    fn supports_cov(&self) -> bool {
        self.called("supports_cov", ());
        true
    }
    fn supports_subscribe_cov_property(&self) -> bool {
        self.called("supports_subscribe_cov_property", ());
        // Unlike the default, which follows `supports_cov`.
        false
    }
    fn take_staging_write_plan_internal(&mut self) -> Option<StagingWritePlan> {
        self.called("take_staging_write_plan_internal", ());
        Some(StagingWritePlan {
            source: self.oid,
            generation: 7,
            priority: 9,
            writes: Vec::new(),
        })
    }
    fn staging_generation_internal(&self) -> Option<u64> {
        self.called("staging_generation_internal", ());
        Some(7)
    }
    fn complete_staging_write_plan_internal(&mut self, generation: u64, success: bool) -> bool {
        self.called(
            "complete_staging_write_plan_internal",
            (generation, success),
        );
        true
    }
    fn take_command_run_internal(&mut self) -> Option<CommandRun> {
        self.called("take_command_run_internal", ());
        Some(CommandRun {
            source: self.oid,
            generation: 11,
            plan: RunPlan::Actions(Vec::new()),
            chain: std::sync::Arc::from([]),
        })
    }
    fn command_generation_internal(&self) -> Option<u64> {
        self.called("command_generation_internal", ());
        Some(11)
    }
    fn record_command_write_internal(
        &mut self,
        generation: u64,
        command: usize,
        success: bool,
    ) -> bool {
        self.called(
            "record_command_write_internal",
            (generation, command, success),
        );
        true
    }
    fn complete_command_run_internal(&mut self, generation: u64, all_succeeded: bool) -> bool {
        self.called("complete_command_run_internal", (generation, all_succeeded));
        true
    }
    fn enrollment_summary_capability_internal(&self) -> Option<EnrollmentSummaryCapability> {
        self.called("enrollment_summary_capability_internal", ());
        Some(EnrollmentSummaryCapability {
            event_type: EventType::CHANGE_OF_STATE,
            last_transition: None,
        })
    }
    fn supports_cov_property(&self, property: P) -> bool {
        self.called("supports_cov_property", (property,));
        // Unlike the default, which follows `supports_subscribe_cov_property`
        // for every property.
        property == CUSTOM
    }
    fn cov_increment(&self) -> Option<f64> {
        self.called("cov_increment", ());
        Some(1.25)
    }
    fn cov_reported_properties(&self) -> &'static [CovReportedProperty] {
        self.called("cov_reported_properties", ());
        &REPORTED
    }
    fn set_overridden(&mut self, overridden: bool) {
        self.called("set_overridden", (overridden,));
    }
    fn evaluate_intrinsic_reporting(&mut self) -> Option<TransitionOutcome> {
        self.called("evaluate_intrinsic_reporting", ());
        Some(TransitionOutcome {
            change: EventStateChange {
                from: EventState::NORMAL,
                to: EventState::HIGH_LIMIT,
            },
            event_type: EventType::OUT_OF_RANGE,
            distribute: true,
        })
    }
    fn tick_intrinsic_reporting(&mut self) -> Option<TransitionOutcome> {
        self.called("tick_intrinsic_reporting", ());
        Some(TransitionOutcome {
            change: EventStateChange {
                from: EventState::HIGH_LIMIT,
                to: EventState::NORMAL,
            },
            event_type: EventType::OUT_OF_RANGE,
            distribute: false,
        })
    }
    fn commit_event_transition_internal(
        &mut self,
        commit: EventTransitionCommit,
    ) -> Result<(), EventTransitionCommitError> {
        self.called("commit_event_transition_internal", (commit,));
        Ok(())
    }
    fn commit_event_enrollment_reliability_internal(
        &mut self,
        commit: EventEnrollmentReliabilityCommit,
    ) -> Result<(), EventTransitionCommitError> {
        self.called("commit_event_enrollment_reliability_internal", (commit,));
        Ok(())
    }
    fn tick_schedule(
        &mut self,
        today: SpecificDate,
        time: Time,
        calendar_active: &dyn Fn(ObjectIdentifier) -> bool,
    ) -> Option<ScheduleWrite> {
        // The calendar callback is logged by what it answers.
        let calendars = [4, 5].map(|instance| calendar_active(oid(ObjectType::CALENDAR, instance)));
        self.called("tick_schedule", (today, time, calendars));
        Some(schedule_write(2))
    }
    fn take_owed_schedule_writes(&mut self) -> Vec<ScheduleWrite> {
        self.called("take_owed_schedule_writes", ());
        vec![schedule_write(5)]
    }
    fn complete_schedule_write(
        &mut self,
        write: &ScheduleWrite,
        outcomes: &[ScheduleTargetOutcome],
    ) -> bool {
        self.called("complete_schedule_write", (write, outcomes));
        true
    }
    fn calendar_state_internal(&self, date: SpecificDate) -> Option<bool> {
        self.called("calendar_state_internal", (date,));
        Some(date == day())
    }
    fn acknowledge_alarm(&mut self, transition_bit: EventTransitionBits) -> Result<(), Error> {
        self.called("acknowledge_alarm", (transition_bit,));
        Ok(())
    }
    fn acknowledge_alarm_correlated_internal(
        &mut self,
        event_state: EventState,
        timestamp: &BACnetTimeStamp,
    ) -> Result<(), Error> {
        let arguments = (event_state, timestamp);
        self.called("acknowledge_alarm_correlated_internal", arguments);
        Ok(())
    }
    fn acknowledge_alarm_correlated_detailed_internal(
        &mut self,
        event_state: EventState,
        timestamp: &BACnetTimeStamp,
    ) -> Result<Option<EventStateChange>, Error> {
        let arguments = (event_state, timestamp);
        self.called("acknowledge_alarm_correlated_detailed_internal", arguments);
        Ok(Some(EventStateChange {
            from: event_state,
            to: EventState::NORMAL,
        }))
    }
    fn apply_life_safety_operation(
        &mut self,
        operation: LifeSafetyOperation,
    ) -> Result<LifeSafetyOperationOutcome, Error> {
        self.called("apply_life_safety_operation", (operation,));
        Ok(LifeSafetyOperationOutcome {
            effect: LifeSafetyOperationEffect::Applied,
            changed_properties: vec![P::SILENCED],
        })
    }
    fn set_life_safety_operation_expected_internal(
        &mut self,
        operation: LifeSafetyOperation,
    ) -> Result<(), Error> {
        self.called("set_life_safety_operation_expected_internal", (operation,));
        Ok(())
    }
    fn set_event_state_internal(&mut self, state: EventState) -> Result<(), Error> {
        self.called("set_event_state_internal", (state,));
        Ok(())
    }
    fn enrollment_eval_state_internal(&self) -> Option<EventEnrollmentEvalState> {
        self.called("enrollment_eval_state_internal", ());
        Some(EventEnrollmentEvalState::default())
    }
    fn set_enrollment_eval_state_internal(
        &mut self,
        state: EventEnrollmentEvalState,
    ) -> Result<(), Error> {
        self.called("set_enrollment_eval_state_internal", (state,));
        Ok(())
    }
    fn enrollment_eval_source_internal(&self) -> Option<Option<EventEnrollmentMonitoredSource>> {
        self.called("enrollment_eval_source_internal", ());
        Some(Some((self.oid, P::PRESENT_VALUE, Some(2))))
    }
    fn set_enrollment_eval_source_internal(
        &mut self,
        source: Option<EventEnrollmentMonitoredSource>,
    ) -> Result<(), Error> {
        self.called("set_enrollment_eval_source_internal", (source,));
        Ok(())
    }
    fn set_acked_transitions_internal(
        &mut self,
        transition_bit: EventTransitionBits,
        acknowledged: bool,
    ) -> Result<(), Error> {
        let arguments = (transition_bit, acknowledged);
        self.called("set_acked_transitions_internal", arguments);
        Ok(())
    }
    fn evaluate_reliability_internal(&mut self) -> Result<ReliabilityEvaluation, Error> {
        self.called("evaluate_reliability_internal", ());
        Ok(ReliabilityEvaluation::Changed {
            old_reliability: Reliability::NO_SENSOR,
            new_reliability: Reliability::OVER_RANGE,
        })
    }
    fn reliability_evaluation_inhibited_internal(&self) -> bool {
        self.called("reliability_evaluation_inhibited_internal", ());
        true
    }
    fn set_reliability_internal(&mut self, reliability: Reliability) -> Result<(), Error> {
        self.called("set_reliability_internal", (reliability,));
        Ok(())
    }
    fn set_present_value_internal(&mut self, value: PropertyValue) -> Result<(), Error> {
        self.called("set_present_value_internal", (value,));
        Ok(())
    }
    fn set_tracking_value_internal(&mut self, value: PropertyValue) -> Result<(), Error> {
        self.called("set_tracking_value_internal", (value,));
        Ok(())
    }
    fn set_controlled_variable_value_internal(
        &mut self,
        value: PropertyValue,
    ) -> Result<(), Error> {
        self.called("set_controlled_variable_value_internal", (value,));
        Ok(())
    }
    fn add_averaging_sample_internal(
        &mut self,
        sample: Option<PropertyValue>,
    ) -> Result<(), Error> {
        self.called("add_averaging_sample_internal", (sample,));
        Ok(())
    }
    fn take_due_averaging_sample_internal(
        &mut self,
        now: Duration,
    ) -> Option<BACnetObjectPropertyReference> {
        self.called("take_due_averaging_sample_internal", (now,));
        Some(BACnetObjectPropertyReference {
            object_identifier: oid(ObjectType::ANALOG_VALUE, 41),
            property_identifier: P::PRESENT_VALUE.to_raw(),
            property_array_index: Some(2),
        })
    }
    fn audit_log_storage_internal(&self) -> Option<&dyn AuditLogStorage> {
        self.called("audit_log_storage_internal", ());
        self.audit_log.audit_log_storage_internal()
    }
    fn audit_log_forwarding_internal(&self) -> Option<Arc<AuditLogForwarding>> {
        self.called("audit_log_forwarding_internal", ());
        self.audit_log.audit_log_forwarding_internal()
    }
    fn set_audit_log_parent_internal(
        &mut self,
        parent: BACnetDeviceObjectReference,
    ) -> Result<(), Error> {
        self.called("set_audit_log_parent_internal", (parent,));
        Ok(())
    }
    fn audit_log_notification_sink_internal(
        &mut self,
    ) -> Option<&mut dyn AuditLogNotificationSink> {
        self.called("audit_log_notification_sink_internal", ());
        self.audit_log.audit_log_notification_sink_internal()
    }
    fn file_configuration_internal(&self) -> Option<&dyn FileConfiguration> {
        self.called("file_configuration_internal", ());
        Some(&self.file)
    }
    fn file_configuration_internal_mut(&mut self) -> Option<&mut dyn FileConfiguration> {
        self.called("file_configuration_internal_mut", ());
        Some(&mut self.file)
    }
    fn file_storage_internal(&self) -> Option<&dyn FileStorage> {
        self.called("file_storage_internal", ());
        Some(&self.file)
    }
    fn file_storage_internal_mut(&mut self) -> Option<&mut dyn FileStorage> {
        self.called("file_storage_internal_mut", ());
        Some(&mut self.file)
    }
    fn log_record_identities_internal(&self) -> Option<Vec<LogRecordIdentity>> {
        self.called("log_record_identities_internal", ());
        let date = Date {
            year: 126,
            month: 10,
            day: 2,
            day_of_week: 5,
        };
        Some(vec![LogRecordIdentity::new(9, date, noon()).unwrap()])
    }
    fn log_buffer_internal(&self) -> Option<&dyn LogBufferRecords> {
        self.called("log_buffer_internal", ());
        self.trend_log.log_buffer_internal()
    }
    fn add_trend_record(&mut self, record: BACnetLogRecord) -> Result<(), Error> {
        self.called("add_trend_record", (record,));
        // An error of the wrapped object's own, unlike the default's.
        Err(Error::Protocol {
            class: ErrorClass::DEVICE.to_raw() as u32,
            code: ErrorCode::OPERATIONAL_PROBLEM.to_raw() as u32,
        })
    }
    fn add_trend_multiple_record(&mut self, record: BACnetLogMultipleRecord) -> Result<(), Error> {
        self.called("add_trend_multiple_record", (record,));
        // An error of the wrapped object's own, unlike the default's.
        Err(Error::Protocol {
            class: ErrorClass::DEVICE.to_raw() as u32,
            code: ErrorCode::OPERATIONAL_PROBLEM.to_raw() as u32,
        })
    }
    fn add_event_log_record(&mut self, record: BACnetEventLogRecord) -> Result<(), Error> {
        self.called("add_event_log_record", (record,));
        // An error of the wrapped object's own, unlike the default's.
        Err(Error::Protocol {
            class: ErrorClass::DEVICE.to_raw() as u32,
            code: ErrorCode::OPERATIONAL_PROBLEM.to_raw() as u32,
        })
    }
}

/// A probe's identity and readings, every provided method left at the trait
/// default: what an adapter that forwarded nothing more would answer.
pub struct Defaults(pub Probe);

impl BACnetObject for Defaults {
    fn object_identifier(&self) -> ObjectIdentifier {
        self.0.object_identifier()
    }
    fn object_name(&self) -> &str {
        self.0.object_name()
    }
    fn read_property(&self, property: P, index: Option<u32>) -> Result<PropertyValue, Error> {
        self.0.read_property(property, index)
    }
    fn write_property(
        &mut self,
        property: P,
        index: Option<u32>,
        value: PropertyValue,
        priority: Option<u8>,
    ) -> Result<(), Error> {
        self.0.write_property(property, index, value, priority)
    }
    fn property_list(&self) -> Cow<'static, [P]> {
        self.0.property_list()
    }
}
