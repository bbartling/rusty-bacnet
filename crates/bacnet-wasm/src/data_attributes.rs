//! BACnet/SC Data Option mapping for WASM/browser clients.

use crate::sc_frame::{ScFunction, ScMessage, ScOption, BROADCAST_VMAC};
use bacnet_types::enums::{ErrorClass, ErrorCode};
use bacnet_types::error::Error;
use bytes::Bytes;
use serde::{Deserialize, Serialize};

const MAX_SC_DATA_ATTRIBUTES: usize = 64;
const SECURE_PATH_OPTION_TYPE: u8 = 1;

/// Data-link attribute carried by BACnet/SC Data Options.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DataAttribute {
    /// Attribute/header option type. BACnet/SC uses values 1..31.
    #[serde(alias = "optionType")]
    pub option_type: u8,
    /// Whether the final consumer must understand this attribute.
    #[serde(alias = "mustUnderstand")]
    pub must_understand: bool,
    /// Attribute payload bytes, if any.
    pub data: Vec<u8>,
}

pub(crate) fn from_data_options(msg: &ScMessage) -> Vec<DataAttribute> {
    msg.data_options
        .iter()
        .map(|option| DataAttribute {
            option_type: option.option_type,
            must_understand: option.must_understand,
            data: option.data.clone(),
        })
        .collect()
}

pub(crate) fn to_data_options(data_attributes: &[DataAttribute]) -> Result<Vec<ScOption>, Error> {
    if data_attributes.len() > MAX_SC_DATA_ATTRIBUTES {
        return Err(Error::Encoding(format!(
            "BACnet/SC Data Options exceed {MAX_SC_DATA_ATTRIBUTES} attributes"
        )));
    }

    data_attributes
        .iter()
        .map(|attribute| {
            if !(1..=31).contains(&attribute.option_type) {
                return Err(Error::Encoding(format!(
                    "BACnet/SC Data Option type must be 1..31, got {}",
                    attribute.option_type
                )));
            }
            if attribute.data.len() > u16::MAX as usize {
                return Err(Error::Encoding(format!(
                    "BACnet/SC Data Option type {} payload length {} exceeds 65535",
                    attribute.option_type,
                    attribute.data.len()
                )));
            }

            Ok(ScOption {
                option_type: attribute.option_type,
                must_understand: attribute.must_understand,
                data: attribute.data.clone(),
            })
        })
        .collect()
}

pub(crate) fn unsupported_must_understand_data_option(msg: &ScMessage) -> Option<&ScOption> {
    if msg.function != ScFunction::EncapsulatedNpdu {
        return None;
    }

    msg.data_options
        .iter()
        .find(|option| option.must_understand && !is_understood_data_option(option))
}

pub(crate) fn option_header_marker(option: &ScOption) -> u8 {
    let mut marker = option.option_type & 0x1F;
    if option.must_understand {
        marker |= 0x40;
    }
    if !option.data.is_empty() {
        marker |= 0x20;
    }
    marker
}

pub(crate) fn unsupported_must_understand_result(msg: &ScMessage) -> Option<Option<ScMessage>> {
    let option = unsupported_must_understand_data_option(msg)?;
    if msg.destination_vmac == Some(BROADCAST_VMAC) {
        return Some(None);
    }

    Some(Some(build_bvlc_result_nak(
        msg.message_id,
        msg.function,
        option_header_marker(option),
        ErrorClass::COMMUNICATION,
        ErrorCode::HEADER_NOT_UNDERSTOOD,
    )))
}

fn build_bvlc_result_nak(
    message_id: u16,
    result_for: ScFunction,
    error_header_marker: u8,
    error_class: ErrorClass,
    error_code: ErrorCode,
) -> ScMessage {
    let error_class = error_class.to_raw().to_be_bytes();
    let error_code = error_code.to_raw().to_be_bytes();
    ScMessage {
        function: ScFunction::Result,
        message_id,
        originating_vmac: None,
        destination_vmac: None,
        dest_options: Vec::new(),
        data_options: Vec::new(),
        payload: Bytes::from(vec![
            result_for.to_raw(),
            0x01,
            error_header_marker,
            error_class[0],
            error_class[1],
            error_code[0],
            error_code[1],
        ]),
    }
}

fn is_understood_data_option(option: &ScOption) -> bool {
    option.option_type == SECURE_PATH_OPTION_TYPE
}
