//! The full-server Device view answers every read-only `BACnetObject` query
//! with the wrapped object's own answer, and keeps answers of its own only
//! where a Device's executor-owned properties need them (#1076).
//!
//! The trait's methods are read from its source, so a query added there fails
//! `every_read_query_has_a_forwarding_check` until it gets a row in
//! `QUERIES`. Each row renders one query's answer; the probe answers every
//! one in a way no trait default can reproduce, so a view that forgot to
//! forward a query reads differently from the probe.

use super::*;
use bacnet_objects::audit::{AuditLogObject, AuditLogPersistence, AuditLogSnapshot};
use bacnet_objects::file::FileObject;
use bacnet_types::constructed::BACnetDeviceObjectReference;
use bacnet_types::enums::{AuditLevel, EventType};
use bacnet_types::primitives::{Date, Time};
use std::collections::BTreeSet;

const TRAIT_SOURCE: &str = include_str!("../../bacnet-objects/src/traits.rs");

const CUSTOM: P = P::from_raw(5000);
const CUSTOM_LIST: P = P::from_raw(5001);
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

/// One `BACnetObject` method as the trait declares it.
struct Declared {
    name: &'static str,
    /// Takes `&self`: a query the view can forward.
    shared: bool,
    /// Has no default body.
    required: bool,
}

/// Every method of `BACnetObject`, from the trait's source. rustfmt puts each
/// declaration at four spaces, and the trait's closing brace at column 0.
fn declared() -> Vec<Declared> {
    let start = TRAIT_SOURCE
        .find("pub trait BACnetObject")
        .expect("trait declared");
    let body = &TRAIT_SOURCE[start..];
    let body = &body[..body.find("\n}\n").expect("trait closes")];
    body.match_indices("\n    fn ")
        .map(|(offset, marker)| {
            let signature = &body[offset + marker.len()..];
            let open = signature.find('(').expect("parameter list");
            let parameters = &signature[open..];
            let receiver = &parameters[..parameters.find("self").expect("method")];
            assert!(!receiver.contains(')'), "{signature:.60} takes no receiver");
            let required = match (signature.find(';'), signature.find('{')) {
                (Some(semicolon), Some(brace)) => semicolon < brace,
                (semicolon, _) => semicolon.is_some(),
            };
            Declared {
                name: &signature[..open],
                shared: !receiver.contains("&mut"),
                required,
            }
        })
        .collect()
}

type Query = fn(&dyn BACnetObject) -> String;

fn address<T: ?Sized>(reference: &T) -> String {
    format!("{:p}", std::ptr::from_ref(reference).cast::<()>())
}

fn day() -> SpecificDate {
    SpecificDate::new(2026, 10, 2).unwrap()
}

/// One rendered answer per read-only query. Capabilities render as the
/// address they borrow, so forwarding must hand out the object's own.
const QUERIES: &[(&str, Query)] = &[
    ("audit_object_policy_internal", |o| {
        format!("{:?}", o.audit_object_policy_internal())
    }),
    ("audit_reporter_internal", |o| {
        format!("{:?}", o.audit_reporter_internal().map(address))
    }),
    ("object_identifier", |o| {
        format!("{:?}", o.object_identifier())
    }),
    ("object_name", |o| o.object_name().to_owned()),
    ("read_property", |o| {
        format!("{:?}", o.read_property(CUSTOM, None))
    }),
    ("property_metadata", |o| {
        format!("{:?}", o.property_metadata())
    }),
    ("property_list", |o| format!("{:?}", o.property_list())),
    ("next_monotonic_deadline_internal", |o| {
        format!("{:?}", o.next_monotonic_deadline_internal())
    }),
    ("cov_snapshot_internal", |o| {
        format!(
            "{:?}",
            o.cov_snapshot_internal()
                .map(|snapshot| snapshot.object_name().to_owned())
        )
    }),
    ("binary_lighting_blink_count_internal", |o| {
        o.binary_lighting_blink_count_internal().to_string()
    }),
    ("is_writable_property", |o| {
        format!(
            "{:?}",
            [CUSTOM, P::DESCRIPTION].map(|p| o.is_writable_property(p))
        )
    }),
    ("is_array_property", |o| {
        format!(
            "{:?}",
            [CUSTOM, P::PRIORITY_ARRAY].map(|p| o.is_array_property(p))
        )
    }),
    ("is_list_property", |o| {
        format!(
            "{:?}",
            [CUSTOM_LIST, P::DATE_LIST].map(|p| o.is_list_property(p))
        )
    }),
    ("is_createable", |o| o.is_createable().to_string()),
    ("is_deleteable", |o| o.is_deleteable().to_string()),
    ("required_properties", |o| {
        format!("{:?}", o.required_properties())
    }),
    ("supports_cov", |o| o.supports_cov().to_string()),
    // Rendered beside `supports_cov`: the probe's false must differ both from
    // an all-default object (false, false) and from a view that kept the
    // default, which follows the forwarded `supports_cov` (true, true).
    ("supports_subscribe_cov_property", |o| {
        format!(
            "{:?}",
            [o.supports_cov(), o.supports_subscribe_cov_property()]
        )
    }),
    ("staging_generation_internal", |o| {
        format!("{:?}", o.staging_generation_internal())
    }),
    ("enrollment_summary_capability_internal", |o| {
        format!("{:?}", o.enrollment_summary_capability_internal())
    }),
    ("supports_cov_property", |o| {
        format!(
            "{:?}",
            [CUSTOM, P::DESCRIPTION].map(|p| o.supports_cov_property(p))
        )
    }),
    ("cov_increment", |o| format!("{:?}", o.cov_increment())),
    ("cov_reported_properties", |o| {
        format!("{:?}", o.cov_reported_properties())
    }),
    ("calendar_state_internal", |o| {
        format!("{:?}", o.calendar_state_internal(day()))
    }),
    ("enrollment_eval_state_internal", |o| {
        format!("{:?}", o.enrollment_eval_state_internal())
    }),
    ("enrollment_eval_source_internal", |o| {
        format!("{:?}", o.enrollment_eval_source_internal())
    }),
    ("reliability_evaluation_inhibited_internal", |o| {
        o.reliability_evaluation_inhibited_internal().to_string()
    }),
    ("audit_log_storage_internal", |o| {
        format!("{:?}", o.audit_log_storage_internal().map(address))
    }),
    ("audit_log_forwarding_internal", |o| {
        format!(
            "{:?}",
            o.audit_log_forwarding_internal()
                .map(|forwarding| address(forwarding.as_ref()))
        )
    }),
    ("file_configuration_internal", |o| {
        format!("{:?}", o.file_configuration_internal().map(address))
    }),
    ("file_storage_internal", |o| {
        format!("{:?}", o.file_storage_internal().map(address))
    }),
    ("log_record_identities_internal", |o| {
        format!("{:?}", o.log_record_identities_internal())
    }),
];

struct NoPersistence;

impl AuditLogPersistence for NoPersistence {
    fn load(&self, _: ObjectIdentifier) -> Result<Option<AuditLogSnapshot>, Error> {
        Ok(None)
    }
    fn commit(&self, _: &AuditLogSnapshot) -> Result<(), Error> {
        Ok(())
    }
}

/// Answers every query of the trait, none the way its default would.
struct Probe {
    oid: ObjectIdentifier,
    reporter: AuditReporterObject,
    audit_log: AuditLogObject,
    file: FileObject,
}

impl Probe {
    fn new(object_type: ObjectType) -> Self {
        let mut audit_log =
            AuditLogObject::new(3, "Probe log", 4, Arc::new(NoPersistence)).unwrap();
        audit_log.set_member_of(Some(BACnetDeviceObjectReference {
            device_identifier: None,
            object_identifier: ObjectIdentifier::new(ObjectType::AUDIT_LOG, 9).unwrap(),
        }));
        Self {
            oid: ObjectIdentifier::new(object_type, 1).unwrap(),
            reporter: AuditReporterObject::new(17, "Probe reporter").unwrap(),
            audit_log,
            file: FileObject::new(5, "Probe file", "test").unwrap(),
        }
    }
}

impl BACnetObject for Probe {
    fn audit_object_policy_internal(&self) -> ObjectAuditPolicy {
        ObjectAuditPolicy {
            level: Some(AuditLevel::AUDIT_ALL),
            ..ObjectAuditPolicy::default()
        }
    }
    fn audit_reporter_internal(&self) -> Option<&AuditReporterObject> {
        Some(&self.reporter)
    }
    fn object_identifier(&self) -> ObjectIdentifier {
        self.oid
    }
    fn object_name(&self) -> &str {
        "Probe"
    }
    fn read_property(&self, property: P, _: Option<u32>) -> Result<PropertyValue, Error> {
        if property == CUSTOM {
            Ok(PropertyValue::Unsigned(7))
        } else {
            Err(property_error(ErrorCode::UNKNOWN_PROPERTY))
        }
    }
    fn write_property(
        &mut self,
        _: P,
        _: Option<u32>,
        _: PropertyValue,
        _: Option<u8>,
    ) -> Result<(), Error> {
        Err(property_error(ErrorCode::WRITE_ACCESS_DENIED))
    }
    fn property_metadata(&self) -> Cow<'_, [PropertyMetadata]> {
        Cow::Borrowed(&METADATA)
    }
    fn property_list(&self) -> Cow<'static, [P]> {
        Cow::Borrowed(&[P::OBJECT_IDENTIFIER, P::OBJECT_NAME, P::OBJECT_TYPE, CUSTOM])
    }
    fn next_monotonic_deadline_internal(&self) -> Option<Duration> {
        Some(Duration::from_secs(99))
    }
    fn cov_snapshot_internal(&self) -> Option<Box<dyn BACnetObject>> {
        Some(Box::new(
            AuditReporterObject::new(18, "Probe snapshot").unwrap(),
        ))
    }
    fn binary_lighting_blink_count_internal(&self) -> u64 {
        123
    }
    fn is_writable_property(&self, property: P) -> bool {
        property == CUSTOM
    }
    fn is_array_property(&self, property: P) -> bool {
        property == CUSTOM
    }
    fn is_list_property(&self, property: P) -> bool {
        property == CUSTOM_LIST
    }
    fn is_createable(&self) -> bool {
        true
    }
    fn is_deleteable(&self) -> bool {
        false
    }
    fn required_properties(&self) -> Cow<'static, [P]> {
        Cow::Borrowed(&[CUSTOM])
    }
    fn supports_cov(&self) -> bool {
        true
    }
    fn supports_subscribe_cov_property(&self) -> bool {
        // Unlike the default, which follows `supports_cov`.
        false
    }
    fn staging_generation_internal(&self) -> Option<u64> {
        Some(7)
    }
    fn enrollment_summary_capability_internal(&self) -> Option<EnrollmentSummaryCapability> {
        Some(EnrollmentSummaryCapability {
            event_type: EventType::CHANGE_OF_STATE,
            last_transition: None,
        })
    }
    fn supports_cov_property(&self, property: P) -> bool {
        // Unlike the default, which follows `supports_subscribe_cov_property`
        // for every property.
        property == CUSTOM
    }
    fn cov_increment(&self) -> Option<f32> {
        Some(1.25)
    }
    fn cov_reported_properties(&self) -> &'static [CovReportedProperty] {
        &REPORTED
    }
    fn calendar_state_internal(&self, date: SpecificDate) -> Option<bool> {
        Some(date == day())
    }
    fn enrollment_eval_state_internal(&self) -> Option<EventEnrollmentEvalState> {
        Some(EventEnrollmentEvalState::default())
    }
    fn enrollment_eval_source_internal(&self) -> Option<Option<EventEnrollmentMonitoredSource>> {
        Some(Some((self.oid, P::PRESENT_VALUE, Some(2))))
    }
    fn reliability_evaluation_inhibited_internal(&self) -> bool {
        true
    }
    fn audit_log_storage_internal(&self) -> Option<&dyn AuditLogStorage> {
        self.audit_log.audit_log_storage_internal()
    }
    fn audit_log_forwarding_internal(&self) -> Option<Arc<AuditLogForwarding>> {
        self.audit_log.audit_log_forwarding_internal()
    }
    fn file_configuration_internal(&self) -> Option<&dyn FileConfiguration> {
        Some(&self.file)
    }
    fn file_storage_internal(&self) -> Option<&dyn FileStorage> {
        Some(&self.file)
    }
    fn log_record_identities_internal(&self) -> Option<Vec<LogRecordIdentity>> {
        let date = Date {
            year: 126,
            month: 10,
            day: 2,
            day_of_week: 5,
        };
        let time = Time {
            hour: 12,
            minute: 0,
            second: 0,
            hundredths: 0,
        };
        Some(vec![LogRecordIdentity::new(9, date, time).unwrap()])
    }
}

/// The wrapped object's identity and readings, every provided query left at
/// the trait default: what a view that forwarded nothing more would answer.
struct Defaults<'a>(&'a dyn BACnetObject);

impl BACnetObject for Defaults<'_> {
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
        _: P,
        _: Option<u32>,
        _: PropertyValue,
        _: Option<u8>,
    ) -> Result<(), Error> {
        Err(property_error(ErrorCode::WRITE_ACCESS_DENIED))
    }
    fn property_list(&self) -> Cow<'static, [P]> {
        self.0.property_list()
    }
}

#[test]
fn every_read_query_has_a_forwarding_check() {
    let declared = declared();
    let method = |name| declared.iter().find(|method| method.name == name).unwrap();
    // The reading is sound: one shared required query, one mutating required
    // method, one shared provided query, one multi-line mutating signature.
    assert!(method("object_identifier").shared && method("object_identifier").required);
    assert!(!method("write_property").shared && method("write_property").required);
    assert!(method("is_list_property").shared && !method("is_list_property").required);
    assert!(!method("audit_policy_authority_internal").shared);
    let queries: BTreeSet<_> = declared
        .iter()
        .filter(|method| method.shared)
        .map(|method| method.name)
        .collect();
    let checked: BTreeSet<_> = QUERIES.iter().map(|(name, _)| *name).collect();
    assert_eq!(checked.len(), QUERIES.len(), "a query has two rows");
    assert_eq!(
        checked, queries,
        "give every read-only BACnetObject query a row here and a forwarder in DeviceReadView"
    );
}

#[test]
fn the_view_forwards_every_read_query() {
    let db = ObjectDatabase::new();
    let context = DeviceReadContext::new(&db, DeviceExecution::FullServer, None);
    let probe = Probe::new(ObjectType::ANALOG_VALUE);
    let view = context.object(&probe);
    let required: BTreeSet<_> = declared()
        .into_iter()
        .filter(|method| method.required)
        .map(|method| method.name)
        .collect();
    for (name, query) in QUERIES {
        let answer = query(&probe);
        if !required.contains(name) {
            assert_ne!(
                answer,
                query(&Defaults(&probe)),
                "{name}: the probe must answer unlike the trait default"
            );
        }
        assert_eq!(query(&view), answer, "{name}: the view must forward it");
    }
}

#[test]
fn a_device_keeps_its_owned_answers_and_forwards_every_other_query() {
    // The rows the view answers itself for a Device, to serve the
    // executor-owned properties and keep them out of any frozen copy.
    const OWNED: [&str; 4] = [
        "property_metadata",
        "property_list",
        "required_properties",
        "cov_snapshot_internal",
    ];
    let db = ObjectDatabase::new();
    let context = DeviceReadContext::new(&db, DeviceExecution::FullServer, None);
    let probe = Probe::new(ObjectType::DEVICE);
    let view = context.object(&probe);
    for (name, query) in QUERIES {
        if OWNED.contains(name) {
            assert_ne!(query(&view), query(&probe), "{name}: the view answers it");
        } else {
            assert_eq!(
                query(&view),
                query(&probe),
                "{name}: the view must forward it"
            );
        }
    }
    assert_eq!(view.cov_snapshot_internal().map(|_| ()), None);
    assert!(view
        .property_list()
        .contains(&P::PROTOCOL_SERVICES_SUPPORTED));
}
