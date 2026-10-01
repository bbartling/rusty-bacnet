//! Matching and decoding of BVLC management responses for the B/IP client
//! helpers (`read_bdt`, `write_bdt`, `read_fdt`, `delete_fdt_entry`,
//! `register_foreign_device_bvlc`).

use tokio::sync::oneshot;

use crate::bvll::BvllMessage;
use bacnet_types::enums::{BvlcFunction, BvlcResultCode};
use bacnet_types::error::Error;

#[derive(Clone, Copy, PartialEq, Eq)]
pub(super) enum BvlcResponseKind {
    Result,
    ReadBroadcastDistributionTableAck,
    ReadForeignDeviceTableAck,
}

impl BvlcResponseKind {
    pub(super) fn accepts(self, function: BvlcFunction) -> bool {
        match self {
            Self::Result => function == BvlcFunction::BVLC_RESULT,
            Self::ReadBroadcastDistributionTableAck => {
                function == BvlcFunction::READ_BROADCAST_DISTRIBUTION_TABLE_ACK
                    || function == BvlcFunction::BVLC_RESULT
            }
            Self::ReadForeignDeviceTableAck => {
                function == BvlcFunction::READ_FOREIGN_DEVICE_TABLE_ACK
                    || function == BvlcFunction::BVLC_RESULT
            }
        }
    }
}

pub(super) struct PendingBvlcResponse {
    pub(super) target: ([u8; 4], u16),
    pub(super) expected: BvlcResponseKind,
    pub(super) tx: oneshot::Sender<BvllMessage>,
}

impl PendingBvlcResponse {
    pub(super) fn matches(&self, sender: ([u8; 4], u16), function: BvlcFunction) -> bool {
        self.target == sender && self.expected.accepts(function)
    }
}

pub(super) fn expect_bvlc_function(msg: &BvllMessage, expected: BvlcFunction) -> Result<(), Error> {
    if msg.function == expected {
        Ok(())
    } else {
        Err(Error::Encoding(format!(
            "expected BVLC response {expected:?}, got {:?}",
            msg.function
        )))
    }
}

pub(super) fn decode_bvlc_result_code(msg: &BvllMessage) -> Result<BvlcResultCode, Error> {
    expect_bvlc_function(msg, BvlcFunction::BVLC_RESULT)?;
    if msg.payload.len() != std::mem::size_of::<u16>() {
        return Err(Error::Encoding(format!(
            "BVLC-Result payload must be 2 bytes, got {}",
            msg.payload.len()
        )));
    }

    Ok(BvlcResultCode::from_raw(u16::from_be_bytes([
        msg.payload[0],
        msg.payload[1],
    ])))
}

pub(super) fn bvlc_result_error(msg: &BvllMessage) -> Error {
    match decode_bvlc_result_code(msg) {
        Ok(code) => Error::Encoding(format!("BVLC-Result: {code:?}")),
        Err(err) => err,
    }
}
