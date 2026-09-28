//! Original-ingress authority for an application response.
use crate::layer::ReceivedApdu;
use bacnet_transport::port::{DirectResponse, TransportProvenance};

/// Saved response route, independent of the request's claimed BACnet addresses.
///
/// Verified direct ingress requires a matching original-socket capability.
/// Missing or mismatched capability fails closed; other ingress retains normal
/// addressing. Clones do not retain a socket or extend its membership lifetime.
#[derive(Clone, Debug)]
pub struct ResponseRoute {
    provenance: TransportProvenance,
    direct: Option<DirectResponse>,
}

impl ResponseRoute {
    /// Capture immutable ingress provenance and its optional direct capability.
    /// A supplied capability is checked against provenance at every send.
    pub fn new(provenance: TransportProvenance, direct: Option<DirectResponse>) -> Self {
        Self { provenance, direct }
    }

    /// Plain, non-direct addressing for locally constructed legacy envelopes.
    pub fn unverified() -> Self {
        Self::new(TransportProvenance::unverified(), None)
    }

    /// Original authentication scope; this never follows a replacement peer.
    pub fn provenance(&self) -> TransportProvenance {
        self.provenance
    }

    pub(crate) fn direct(&self) -> Result<Option<&DirectResponse>, bacnet_types::error::Error> {
        match (self.provenance.direct_sc_identity(), self.direct.as_ref()) {
            (Some(identity), Some(route)) if identity == route.identity() => Ok(Some(route)),
            (None, None) => Ok(None),
            _ => Err(bacnet_types::error::Error::Transport(std::io::Error::new(
                std::io::ErrorKind::PermissionDenied,
                "missing or mismatched original direct response capability",
            ))),
        }
    }
}

impl ReceivedApdu {
    /// Save this ingress's response route before moving it into queued work.
    pub fn response_route(&self) -> ResponseRoute {
        ResponseRoute::new(self.provenance, self.direct_response.clone())
    }
}
