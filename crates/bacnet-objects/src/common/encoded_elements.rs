//! Splitting a written array or list whose elements are constructed values
//! that reach the object as raw octets (`PropertyValue::ApplicationData`).

use bacnet_encoding::tags::{self, Tag};
use bacnet_types::error::Error;
use bacnet_types::primitives::PropertyValue;

/// A shared codec for one element: the element and the offset past it.
pub(crate) type ElementDecoder<T> = fn(&[u8], usize) -> Result<(T, usize), Error>;

/// The byte chunks of a written value: the raw payload, or the elements of a
/// value as a read returns it.
pub(crate) fn chunks(value: PropertyValue) -> Result<Vec<Vec<u8>>, Error> {
    match value {
        PropertyValue::ApplicationData(bytes) => Ok(vec![bytes]),
        PropertyValue::List(elements) => elements
            .into_iter()
            .map(|element| match element {
                PropertyValue::ApplicationData(bytes) => Ok(bytes),
                _ => Err(super::invalid_data_type_error()),
            })
            .collect(),
        _ => Err(super::invalid_data_type_error()),
    }
}

/// Decode every element in `value`, back to back within each chunk.
///
/// `starts` says whether a tag can begin an element of the property's
/// datatype; `decode` is the shared codec for one element. An element that
/// starts with any other tag is INVALID_DATA_TYPE, one that doesn't decode
/// INVALID_DATA_ENCODING.
pub(crate) fn decode_elements<T>(
    value: PropertyValue,
    starts: fn(&Tag) -> bool,
    decode: ElementDecoder<T>,
) -> Result<Vec<T>, Error> {
    let mut elements = Vec::new();
    for bytes in chunks(value)? {
        let mut offset = 0;
        while offset < bytes.len() {
            let (element, end) = decode_element(&bytes, offset, starts, decode)?;
            elements.push(element);
            offset = end;
        }
    }
    Ok(elements)
}

/// Decode the element at `offset`, with the errors [`decode_elements`]
/// describes, returning it and the offset past it.
pub(crate) fn decode_element<T>(
    bytes: &[u8],
    offset: usize,
    starts: fn(&Tag) -> bool,
    decode: ElementDecoder<T>,
) -> Result<(T, usize), Error> {
    match tags::decode_tag(bytes, offset) {
        Ok((tag, _)) if starts(&tag) => {}
        Ok(_) => return Err(super::invalid_data_type_error()),
        Err(_) => return Err(super::invalid_data_encoding_error()),
    }
    decode(bytes, offset).map_err(|_| super::invalid_data_encoding_error())
}
