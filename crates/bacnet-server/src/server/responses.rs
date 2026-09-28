use super::*;

impl<T: TransportPort + 'static> BACnetServer<T> {
    /// Terminal ordinary response: release the pending owner only after NPDU
    /// encoding, at local issuance. Failure/cancellation also drops ownership.
    pub(super) async fn issue_terminal_response(
        network: &NetworkLayer<T>,
        apdu: &[u8],
        source_mac: &[u8],
        source_network: Option<&NpduAddress>,
        pending: Option<PendingConfirmedRequest>,
    ) -> Result<(), Error> {
        network
            .send_apdu_on_issuance(
                apdu,
                source_mac,
                source_network,
                false,
                NetworkPriority::NORMAL,
                move || drop(pending),
            )
            .await
    }

    pub(super) async fn send_confirmed_response_apdu(
        network: &NetworkLayer<T>,
        apdu: &[u8],
        source_mac: &[u8],
        source_network: Option<&NpduAddress>,
    ) -> Result<(), Error> {
        Self::send_confirmed_response_apdu_expecting_reply(
            network,
            apdu,
            source_mac,
            source_network,
            false,
        )
        .await
    }

    pub(super) async fn send_confirmed_response_apdu_expecting_reply(
        network: &NetworkLayer<T>,
        apdu: &[u8],
        source_mac: &[u8],
        source_network: Option<&NpduAddress>,
        expecting_reply: bool,
    ) -> Result<(), Error> {
        if let Some(destination) = source_network {
            network
                .send_apdu_routed(
                    apdu,
                    destination.network,
                    &destination.mac_address,
                    source_mac,
                    expecting_reply,
                    NetworkPriority::NORMAL,
                )
                .await
        } else {
            network
                .send_apdu(apdu, source_mac, expecting_reply, NetworkPriority::NORMAL)
                .await
        }
    }
}
