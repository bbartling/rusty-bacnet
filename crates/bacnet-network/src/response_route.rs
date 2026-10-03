//! Original-ingress authority for an application response.
use crate::layer::ReceivedApdu;
use bacnet_encoding::npdu::{encode_npdu, Npdu, NpduAddress};
use bacnet_transport::port::{DirectResponse, TransportProvenance};
use bacnet_types::{enums::NetworkPriority, error::Error};
use bytes::{Bytes, BytesMut};

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

    /// Cap an APDU by the original direct peer's NPDU/BVLC receive limits,
    /// including the actual local or routed response NPDU header. Non-direct
    /// ingress keeps the supplied APDU cap. Invalid authority/addressing is an
    /// error; retirement does not invalidate this immutable sizing snapshot.
    pub fn max_apdu_length(
        &self,
        apdu_limit: u16,
        destination: Option<&NpduAddress>,
    ) -> Result<u16, Error> {
        let Some(direct) = self.direct()? else {
            return Ok(apdu_limit);
        };
        let header = encode_response_npdu(&[], destination, false, NetworkPriority::NORMAL)?;
        let available = direct.max_npdu_length().saturating_sub(header.len());
        Ok(usize::from(apdu_limit).min(available) as u16)
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

/// Shared framing for budget calculation and actual response issuance.
pub(crate) fn encode_response_npdu(
    apdu: &[u8],
    destination: Option<&NpduAddress>,
    expecting_reply: bool,
    priority: NetworkPriority,
) -> Result<BytesMut, Error> {
    if let Some(destination) = destination {
        crate::layer::check_destination(
            destination,
            "pass no destination (no DNET) for a local peer",
        )?;
    }
    let npdu = Npdu {
        destination: destination.cloned(),
        expecting_reply,
        priority,
        payload: Bytes::copy_from_slice(apdu),
        ..Npdu::default()
    };
    let mut encoded = BytesMut::new();
    encode_npdu(&mut encoded, &npdu)?;
    Ok(encoded)
}
