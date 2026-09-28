//! Transfer original-ingress metadata to every local router delivery branch.
use super::*;
use bacnet_transport::port::ReceivedNpdu;

pub(super) fn application(
    received: ReceivedNpdu,
    npdu: Npdu,
    port_network: u16,
    is_group: bool,
) -> ReceivedApdu {
    ReceivedApdu {
        apdu: npdu.payload,
        source_mac: received.source_mac,
        ingress_network: Some(port_network),
        source_network: npdu.source,
        link_layer_group: received.link_layer_group,
        is_group,
        data_attributes: received.data_attributes,
        provenance: received.provenance,
        direct_response: received.direct_response,
        reply_tx: received.reply_tx,
    }
}
