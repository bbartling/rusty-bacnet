use super::*;

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
        let buf = if let Some(destination) = destination {
            Self::encode_routed_npdu_buf(
                apdu,
                destination.network,
                &destination.mac_address,
                expecting_reply,
                priority,
            )?
        } else {
            let npdu = Npdu {
                expecting_reply,
                priority,
                payload: Bytes::copy_from_slice(apdu),
                ..Npdu::default()
            };
            let mut buf = BytesMut::with_capacity(2 + apdu.len());
            encode_npdu(&mut buf, &npdu)?;
            buf
        };
        on_issuance();
        self.transport
            .send_unicast_with_data_attributes(&buf, next_hop, &[])
            .await
    }
}
