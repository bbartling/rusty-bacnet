use super::*;

/// Delivery endpoint, including the immediate router for routed traffic.
/// Ordinary and Single keys use it as identity; Multiple keys use the recipient.
/// Quota grouping deliberately uses the separate [`CovPeerKey`].
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct SubscriberEndpoint {
    /// Immediate transport destination (the router when routed).
    pub mac: MacAddr,
    /// Original routed NPDU source, if any.
    pub network: Option<NpduAddress>,
}

impl SubscriberEndpoint {
    /// Capture both parts of the admitted transport endpoint.
    pub fn new(mac: &[u8], network: Option<&NpduAddress>) -> Self {
        Self {
            mac: MacAddr::from_slice(mac),
            network: network.cloned(),
        }
    }
}

/// Original BACnet client address used to match a Multiple context.
/// A routed address is independent of the immediate router; it is a claimed
/// protocol address, not an authentication credential.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum MultipleRecipient {
    /// A local-network client, identified by its source MAC.
    Direct(MacAddr),
    /// The original SNET/SADR of a client behind a router.
    Routed(NpduAddress),
}

impl MultipleRecipient {
    /// Derive client identity separately from the current delivery route.
    pub fn from_endpoint(mac: &[u8], network: Option<&NpduAddress>) -> Self {
        match network {
            Some(source) => Self::Routed(source.clone()),
            None => Self::Direct(MacAddr::from_slice(mac)),
        }
    }
}

/// Multiple notification context. Confirmed and unconfirmed forms are independent.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct MultipleContextKey {
    /// Original client address, without the immediate router.
    pub recipient: MultipleRecipient,
    /// Subscriber's process identifier.
    pub process_id: u32,
    /// Multiple notification form, unlike mutable ordinary/Single mode.
    pub confirmed: bool,
}

/// Complete accepted subscription coordinates used by every table operation.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum CovSubscriptionKey {
    /// Ordinary whole-object subscription.
    Object {
        /// Exact transport and routed endpoint.
        endpoint: SubscriberEndpoint,
        /// Subscriber's process identifier.
        process_id: u32,
        /// Monitored object identifier.
        object: ObjectIdentifier,
    },
    /// Single-property subscription. Absent, zero and element indexes are distinct.
    Property {
        /// Exact transport and routed endpoint.
        endpoint: SubscriberEndpoint,
        /// Subscriber's process identifier.
        process_id: u32,
        /// Monitored object identifier.
        object: ObjectIdentifier,
        /// Monitored property identifier.
        property: PropertyIdentifier,
        /// Optional array coordinate; absence and zero remain distinct.
        index: Option<u32>,
    },
    /// A property reference within a Multiple context.
    Multiple {
        /// Exact Multiple context, including notification form.
        context: MultipleContextKey,
        /// Monitored object identifier.
        object: ObjectIdentifier,
        /// Monitored property identifier.
        property: PropertyIdentifier,
        /// Optional array coordinate; absence and zero remain distinct.
        index: Option<u32>,
    },
}

impl CovSubscriptionKey {
    /// Monitored object shared by all three subscription families.
    pub fn object(&self) -> ObjectIdentifier {
        match self {
            Self::Object { object, .. }
            | Self::Property { object, .. }
            | Self::Multiple { object, .. } => *object,
        }
    }

    /// Matching Multiple context, when this is a Multiple reference.
    pub fn multiple_context(&self) -> Option<&MultipleContextKey> {
        match self {
            Self::Multiple { context, .. } => Some(context),
            _ => None,
        }
    }
}

impl CovSubscription {
    /// Current immediate transport route and original routed source.
    pub fn endpoint(&self) -> SubscriberEndpoint {
        SubscriberEndpoint::new(&self.subscriber_mac, self.subscriber_network.as_ref())
    }

    /// Validate and derive the sole table identity from this proposed subscription.
    pub fn key(&self) -> Result<CovSubscriptionKey, Error> {
        let endpoint =
            SubscriberEndpoint::new(&self.subscriber_mac, self.subscriber_network.as_ref());
        let process_id = self.subscriber_process_identifier;
        let object = self.monitored_object_identifier;
        let index = self.monitored_property_array_index;
        match (self.notification_kind, self.monitored_property, index) {
            (CovNotificationKind::Single, None, None) => Ok(CovSubscriptionKey::Object { endpoint, process_id, object }),
            (CovNotificationKind::Single, Some(property), _) => Ok(CovSubscriptionKey::Property { endpoint, process_id, object, property, index }),
            (CovNotificationKind::Multiple, Some(property), _) => Ok(CovSubscriptionKey::Multiple {
                context: MultipleContextKey { recipient: MultipleRecipient::from_endpoint(&endpoint.mac, endpoint.network.as_ref()), process_id, confirmed: self.issue_confirmed_notifications }, object, property, index,
            }),
            _ => Err(Error::Encoding("COV reference requires a property; whole-object subscriptions cannot carry an index".into())),
        }
    }
}

/// Immutable accepted entry carried through initial notification and fanout work.
/// Only a table can create it. Renewal/recreation invalidates earlier snapshots;
/// snapshots from another table cannot complete this table's entries.
#[derive(Debug, Clone)]
pub struct CovSubscriptionSnapshot {
    pub(super) key: CovSubscriptionKey,
    pub(super) generation: u64,
    pub(super) owner: Arc<()>,
    // Shared by one live Multiple route incarnation; unchanged on same-route
    // refresh. Private so callers cannot forge completion authority.
    pub(super) route_owner: Option<Arc<()>>,
    pub(super) subscription: CovSubscription,
    /// Reported maximum notification delay of a Multiple reference; `None`
    /// for ordinary and Single entries. Never acted on.
    pub(super) max_notification_delay: Option<u32>,
}

impl CovSubscriptionSnapshot {
    /// Canonical identity captured at acceptance.
    pub fn key(&self) -> &CovSubscriptionKey {
        &self.key
    }

    /// Maximum notification delay reported for a Multiple reference (`None`
    /// for ordinary and Single entries). A table-held entry follows every
    /// refresh of its context; a captured snapshot keeps its acceptance value.
    pub fn max_notification_delay(&self) -> Option<u32> {
        self.max_notification_delay
    }
}

impl std::ops::Deref for CovSubscriptionSnapshot {
    type Target = CovSubscription;
    fn deref(&self) -> &Self::Target {
        &self.subscription
    }
}
