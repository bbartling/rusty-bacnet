use crate::port::DataAttribute;
use crate::sc_frame::{ScMessage, ScOption};
use bacnet_types::error::Error;

const MAX_SC_DATA_ATTRIBUTES: usize = 64;

pub(super) fn from_data_options(msg: &ScMessage) -> Vec<DataAttribute> {
    msg.data_options
        .iter()
        .map(|option| DataAttribute {
            option_type: option.option_type,
            must_understand: option.must_understand,
            data: option.data.clone(),
        })
        .collect()
}

pub(super) fn to_data_options(data_attributes: &[DataAttribute]) -> Result<Vec<ScOption>, Error> {
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
