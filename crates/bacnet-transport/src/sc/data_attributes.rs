use crate::port::DataAttribute;
use crate::sc_frame::ScMessage;

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
