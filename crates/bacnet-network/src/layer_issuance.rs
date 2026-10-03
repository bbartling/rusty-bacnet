use super::*;

/// One APDU handed to a local-issuance send.
#[derive(Debug, Clone, Copy)]
pub struct IssuedApdu<'a> {
    /// Encoded APDU to wrap in an NPDU.
    pub apdu: &'a [u8],
    /// Local data-link destination.
    pub next_hop: &'a [u8],
    /// Routed NPDU destination (DNET/DADR), when the peer is behind a router.
    pub destination: Option<&'a NpduAddress>,
    /// Whether the NPDU sets the data-expecting-reply flag.
    pub expecting_reply: bool,
    /// Network priority of the NPDU.
    pub priority: NetworkPriority,
}

impl<T: TransportPort> NetworkLayer<T> {
    /// Seal original-direct response issuance before joining owned server work.
    /// Queued writes observe this irreversible seal; writes already started
    /// remain bounded but cannot be retracted. Network stop/drop also seals.
    pub fn seal_responses(&self) {
        self.response_scope.seal();
    }
}

impl<T: TransportPort + 'static> NetworkLayer<T> {
    /// Issue one local unicast operation after encoding its complete NPDU.
    ///
    /// `destination` selects routed NPDU addressing; `next_hop` is always the
    /// local data-link destination. The synchronous callback runs exactly once
    /// after encoding succeeds, immediately before calling/polling the transport
    /// send. Constructing this future does not call it. Encoding failure never
    /// calls it; later transport failure does not undo issuance. This boundary
    /// does not establish physical emission or remote receipt. A `destination`
    /// on network 0, or on 0xFFFF with a DADR, is an encoding failure.
    ///
    /// Used by server transaction owners whose lifetime ends at local issuance,
    /// independently of the transport future's eventual Result.
    pub async fn send_apdu_on_issuance(
        &self,
        apdu: &[u8],
        next_hop: &[u8],
        destination: Option<&NpduAddress>,
        expecting_reply: bool,
        priority: NetworkPriority,
        on_issuance: impl FnOnce() + Send,
    ) -> Result<(), Error> {
        self.send_response_apdu_on_issuance(
            IssuedApdu {
                apdu,
                next_hop,
                destination,
                expecting_reply,
                priority,
            },
            &crate::response_route::ResponseRoute::unverified(),
            on_issuance,
        )
        .await
    }

    /// Encode and issue a response using its immutable ingress route.
    ///
    /// Direct responses use only the matching original direct socket. A
    /// missing, invalid or stale capability cannot fall back to ordinary unicast.
    /// The callback has the same local issuance contract as
    /// [`Self::send_apdu_on_issuance`]; neither issuance nor success proves receipt.
    pub async fn send_response_apdu_on_issuance(
        &self,
        issued: IssuedApdu<'_>,
        route: &crate::response_route::ResponseRoute,
        on_issuance: impl FnOnce() + Send,
    ) -> Result<(), Error> {
        let IssuedApdu {
            apdu,
            next_hop,
            destination,
            expecting_reply,
            priority,
        } = issued;
        let buf = crate::response_route::encode_response_npdu(
            apdu,
            destination,
            expecting_reply,
            priority,
        )?;
        let direct = route.direct()?;
        on_issuance();
        if let Some(direct) = direct {
            return direct.send(&buf, &self.response_scope).await;
        }
        self.transport
            .send_unicast_with_data_attributes(&buf, next_hop, &[])
            .await
    }
}
