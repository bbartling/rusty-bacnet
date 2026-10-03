//! `BACnetPropertyReference` and `ReadAccessSpecification` (ASHRAE 135-2020
//! Clause 21), shared by the ReadPropertyMultiple request, the COV and Audit
//! services and a Group object's List_Of_Group_Members (Clause 12.14.5).
//!
//! A property reference is the property identifier in context tag `[0]`,
//! then an optional Unsigned array index in `[1]`. A specification is the
//! object identifier in `[0]`, then its references back to back inside an
//! opening/closing `[1]` pair.

use bacnet_types::constructed::{PropertyReference, ReadAccessSpecification};
use bacnet_types::enums::PropertyIdentifier;
use bacnet_types::error::Error;
use bacnet_types::primitives::ObjectIdentifier;
use bytes::BytesMut;

use super::MAX_FRAMED_ITEMS;
use crate::{primitives, tags};

/// Encode one `BACnetPropertyReference`, appending to `buf`.
pub fn encode_property_reference(buf: &mut BytesMut, reference: &PropertyReference) {
    primitives::encode_ctx_unsigned(buf, 0, u64::from(reference.property_identifier.to_raw()));
    if let Some(index) = reference.property_array_index {
        primitives::encode_ctx_unsigned(buf, 1, u64::from(index));
    }
}

/// Decode one `BACnetPropertyReference` at `offset`; returns it and the
/// offset just past it. The array index is read only when the next tag is a
/// primitive context tag `[1]`, so a reference may end the input or be
/// followed by anything else.
pub fn decode_property_reference(
    data: &[u8],
    offset: usize,
) -> Result<(PropertyReference, usize), Error> {
    let (property, mut offset) = decode_ctx_u32(data, offset, 0, "PropertyReference property-id")?;
    let mut property_array_index = None;
    if offset < data.len() {
        let (tag, _) = tags::decode_tag(data, offset)?;
        if tag.is_context(1) {
            let (index, end) = decode_ctx_u32(data, offset, 1, "PropertyReference array-index")?;
            property_array_index = Some(index);
            offset = end;
        }
    }
    Ok((
        PropertyReference {
            property_identifier: PropertyIdentifier::from_raw(property),
            property_array_index,
        },
        offset,
    ))
}

/// Encode one `ReadAccessSpecification`, appending to `buf`. An empty
/// reference list encodes as the bare `[1]` pair; the ReadPropertyMultiple
/// request encoder is what refuses one.
pub fn encode_read_access_specification(buf: &mut BytesMut, spec: &ReadAccessSpecification) {
    primitives::encode_ctx_object_id(buf, 0, &spec.object_identifier);
    tags::encode_opening_tag(buf, 1);
    for reference in &spec.list_of_property_references {
        encode_property_reference(buf, reference);
    }
    tags::encode_closing_tag(buf, 1);
}

/// Decode one `ReadAccessSpecification` at `offset`; returns it and the
/// offset just past its closing `[1]` tag, so a sequence of them is walked
/// by calling this at each element's start.
pub fn decode_read_access_specification(
    data: &[u8],
    offset: usize,
) -> Result<(ReadAccessSpecification, usize), Error> {
    const WHAT: &str = "ReadAccessSpecification";
    let (tag, pos) = tags::decode_tag(data, offset)?;
    if !tag.is_context(0) {
        return Err(Error::decoding(
            offset,
            format!("{WHAT} expected context tag 0"),
        ));
    }
    let end = pos
        .checked_add(tag.length as usize)
        .filter(|&end| end <= data.len())
        .ok_or_else(|| Error::decoding(pos, format!("{WHAT} truncated at object-id")))?;
    let object_identifier = ObjectIdentifier::decode(&data[pos..end])?;

    let (tag, mut offset) = tags::decode_tag(data, end)?;
    if !tag.is_opening_tag(1) {
        return Err(Error::decoding(
            end,
            format!("{WHAT} expected opening tag 1"),
        ));
    }
    let mut list_of_property_references = Vec::new();
    loop {
        if offset >= data.len() {
            return Err(Error::decoding(
                offset,
                format!("{WHAT} missing closing tag 1"),
            ));
        }
        if list_of_property_references.len() >= MAX_FRAMED_ITEMS {
            return Err(Error::decoding(
                offset,
                format!("{WHAT} property references exceed the item limit"),
            ));
        }
        let (tag, tag_end) = tags::decode_tag(data, offset)?;
        if tag.is_closing_tag(1) {
            offset = tag_end;
            break;
        }
        let (reference, next) = decode_property_reference(data, offset)?;
        list_of_property_references.push(reference);
        offset = next;
    }
    Ok((
        ReadAccessSpecification {
            object_identifier,
            list_of_property_references,
        },
        offset,
    ))
}

/// A primitive context tag `tag` holding an Unsigned that fits `u32`.
fn decode_ctx_u32(data: &[u8], offset: usize, tag: u8, what: &str) -> Result<(u32, usize), Error> {
    let (t, pos) = tags::decode_tag(data, offset)?;
    if !t.is_context(tag) {
        return Err(Error::decoding(
            offset,
            format!("{what} expected context tag {tag}"),
        ));
    }
    let end = pos
        .checked_add(t.length as usize)
        .filter(|&end| end <= data.len())
        .ok_or_else(|| Error::decoding(pos, format!("{what} truncated")))?;
    let value = primitives::decode_unsigned(&data[pos..end])?;
    let value =
        u32::try_from(value).map_err(|_| Error::decoding(offset, format!("{what} exceeds u32")))?;
    Ok((value, end))
}
