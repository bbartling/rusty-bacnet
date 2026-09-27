//! Server policy types for LifeSafetyOperation (Clause 13.13).

use std::sync::Arc;

use bacnet_encoding::npdu::NpduAddress;
use bacnet_services::life_safety::LifeSafetyOperationRequest;
use bacnet_types::MacAddr;

/// Network and request identity supplied to a LifeSafetyOperation authorizer.
///
/// `requesting_source` inside [`request`](Self::request) is peer-controlled
/// descriptive text. It is not an authenticated operator identity. For routed
/// traffic, policy should normally consider `source_network` rather than
/// treating the immediate router in `source_mac` as the requester.
#[derive(Clone, PartialEq, Eq)]
pub struct LifeSafetyOperationAuthorizationContext {
    /// Immediate data-link peer (or router) address.
    pub source_mac: MacAddr,
    /// Originating NPDU source when the request was routed.
    pub source_network: Option<NpduAddress>,
    /// Immutable ingress snapshot, retained after the admitting connection closes.
    pub provenance: bacnet_transport::port::TransportProvenance,
    /// Confirmed-request invoke identifier.
    pub invoke_id: u8,
    /// Decoded service request.
    pub request: LifeSafetyOperationRequest,
}

impl LifeSafetyOperationAuthorizationContext {
    /// Original accepted direct-SC leaf and incarnation, separate from claims.
    pub fn direct_sc_identity(&self) -> Option<bacnet_transport::port::DirectScIdentity> {
        self.provenance.direct_sc_identity()
    }
}
impl std::fmt::Debug for LifeSafetyOperationAuthorizationContext {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("LifeSafetyOperationAuthorizationContext")
            .field("source_mac_len", &self.source_mac.len())
            .field(
                "source_network",
                &self
                    .source_network
                    .as_ref()
                    .map(|s| (s.network, s.mac_address.len())),
            )
            .field("provenance", &self.provenance)
            .field("invoke_id", &self.invoke_id)
            .finish_non_exhaustive()
    }
}

/// Thread-safe authorization callback for LifeSafetyOperation.
///
/// The callback must be fast and nonblocking. Returning `false`, panicking, or
/// omitting the callback denies the request before object mutation.
pub type LifeSafetyOperationAuthorizer =
    Arc<dyn Fn(&LifeSafetyOperationAuthorizationContext) -> bool + Send + Sync>;
