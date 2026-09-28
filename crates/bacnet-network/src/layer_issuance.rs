use super::*;

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
    /// does not establish physical emission or remote receipt.
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
            apdu,
            next_hop,
            destination,
            expecting_reply,
            priority,
            &crate::response_route::ResponseRoute::unverified(),
            on_issuance,
        )
        .await
    }

    /// Encode and issue a response using its immutable ingress route.
    ///
    /// Direct responses use only the matching original accepted socket. A
    /// missing, invalid or stale capability cannot fall back to ordinary unicast.
    /// The callback has the same local issuance contract as
    /// [`Self::send_apdu_on_issuance`]; neither issuance nor success proves receipt.
    #[allow(clippy::too_many_arguments)]
    pub async fn send_response_apdu_on_issuance(
        &self,
        apdu: &[u8],
        next_hop: &[u8],
        destination: Option<&NpduAddress>,
        expecting_reply: bool,
        priority: NetworkPriority,
        route: &crate::response_route::ResponseRoute,
        on_issuance: impl FnOnce() + Send,
    ) -> Result<(), Error> {
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
