//! Parameter bundles for the segmentation entry points (#902).

use super::*;

/// Where an inbound segmented ComplexAck came from.
#[derive(Clone, Copy)]
pub(super) struct InboundSegmentSource<'a> {
    /// Immediate MAC the segment arrived from.
    pub(super) mac: &'a [u8],
    /// The peer's SNET/SADR when the segment arrived through a router.
    pub(super) network: &'a Option<NpduAddress>,
    /// Transport provenance snapshot for this segment.
    pub(super) provenance: TransportProvenance,
}

/// Limits and routing state for one segmented confirmed request.
#[derive(Clone, Copy)]
pub(super) struct SegmentedRequestLimits<'a> {
    /// Largest APDU the peer accepts.
    pub(super) remote_max_apdu: u16,
    /// Most segments the peer accepts, when it advertised a bound.
    pub(super) remote_max_segments: Option<u32>,
    /// Forwarded NPCI length reserved for a routed request.
    pub(super) routed_forwarded_npci_len: Option<u16>,
    /// Routed-path lease to mark terminal when the request finishes.
    pub(super) routed_path_lease: Option<&'a RoutedPathLease>,
}
