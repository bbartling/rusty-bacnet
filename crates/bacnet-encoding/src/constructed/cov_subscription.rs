//! Encode and decode the constructed values carried by Device
//! `Active_COV_Subscriptions` and `Active_COV_Multiple_Subscriptions`.
//!
//! Each subscription is a bare Clause 21 sequence. A BACnetLIST concatenates
//! those sequences without adding a list or per-entry wrapper, so each
//! decoder reads one element at `offset` and returns the offset just past
//! it: walking a list calls it at each element's start (#1046).

use bacnet_types::constructed::{
    BACnetCOVMultipleSubscription, BACnetCOVReference, BACnetCOVSubscription,
    BACnetCOVSubscriptionSpecification, BACnetRecipientProcess,
};
use bacnet_types::enums::PropertyIdentifier;
use bacnet_types::error::Error;
use bacnet_types::primitives::ObjectIdentifier;
use bytes::BytesMut;

use crate::{primitives, tags};

use super::{
    decode_ctx_real, decode_ctx_unsigned, decode_object_property_reference, decode_recipient,
    encode_object_property_reference, encode_recipient, expect_closing, expect_opening,
    MAX_FRAMED_ITEMS,
};

/// Encode one bare `BACnetCOVSubscription` sequence.
pub fn encode_cov_subscription(buf: &mut BytesMut, subscription: &BACnetCOVSubscription) {
    tags::encode_opening_tag(buf, 0);
    tags::encode_opening_tag(buf, 0);
    encode_recipient(buf, &subscription.recipient.recipient);
    tags::encode_closing_tag(buf, 0);
    primitives::encode_ctx_unsigned(buf, 1, subscription.recipient.process_identifier as u64);
    tags::encode_closing_tag(buf, 0);

    tags::encode_opening_tag(buf, 1);
    encode_object_property_reference(buf, &subscription.monitored_property_reference);
    tags::encode_closing_tag(buf, 1);

    primitives::encode_ctx_boolean(buf, 2, subscription.issue_confirmed_notifications);
    primitives::encode_ctx_unsigned(buf, 3, subscription.time_remaining as u64);
    if let Some(increment) = subscription.cov_increment {
        primitives::encode_ctx_real(buf, 4, increment);
    }
}

/// Encode a `BACnetLIST of BACnetCOVSubscription` in slice order.
pub fn encode_cov_subscription_list(buf: &mut BytesMut, subscriptions: &[BACnetCOVSubscription]) {
    for subscription in subscriptions {
        encode_cov_subscription(buf, subscription);
    }
}

/// Encode one bare `BACnetCOVMultipleSubscription` sequence: `[0]` recipient
/// process, `[1]` form, `[2]` time remaining, `[3]` maximum notification
/// delay and `[4]` the nested specifications, each an `[0]` object
/// identifier plus `[1]` references of `[0]` BACnetPropertyReference,
/// optional `[1]` REAL increment and `[2]` timestamped flag.
pub fn encode_cov_multiple_subscription(
    buf: &mut BytesMut,
    subscription: &BACnetCOVMultipleSubscription,
) {
    tags::encode_opening_tag(buf, 0);
    tags::encode_opening_tag(buf, 0);
    encode_recipient(buf, &subscription.recipient.recipient);
    tags::encode_closing_tag(buf, 0);
    primitives::encode_ctx_unsigned(buf, 1, subscription.recipient.process_identifier as u64);
    tags::encode_closing_tag(buf, 0);

    primitives::encode_ctx_boolean(buf, 1, subscription.issue_confirmed_notifications);
    primitives::encode_ctx_unsigned(buf, 2, subscription.time_remaining as u64);
    primitives::encode_ctx_unsigned(buf, 3, subscription.max_notification_delay as u64);

    tags::encode_opening_tag(buf, 4);
    for specification in &subscription.list_of_cov_subscription_specifications {
        primitives::encode_ctx_object_id(buf, 0, &specification.monitored_object_identifier);
        tags::encode_opening_tag(buf, 1);
        for reference in &specification.list_of_cov_references {
            tags::encode_opening_tag(buf, 0);
            primitives::encode_ctx_unsigned(buf, 0, reference.property_identifier.to_raw() as u64);
            if let Some(index) = reference.property_array_index {
                primitives::encode_ctx_unsigned(buf, 1, index as u64);
            }
            tags::encode_closing_tag(buf, 0);
            if let Some(increment) = reference.cov_increment {
                primitives::encode_ctx_real(buf, 1, increment);
            }
            primitives::encode_ctx_boolean(buf, 2, reference.timestamped);
        }
        tags::encode_closing_tag(buf, 1);
    }
    tags::encode_closing_tag(buf, 4);
}

/// Encode a `BACnetLIST of BACnetCOVMultipleSubscription` in slice order.
pub fn encode_cov_multiple_subscription_list(
    buf: &mut BytesMut,
    subscriptions: &[BACnetCOVMultipleSubscription],
) {
    for subscription in subscriptions {
        encode_cov_multiple_subscription(buf, subscription);
    }
}

/// Decode one bare `BACnetCOVSubscription` at `offset`; returns it and the
/// offset past its last member.
///
/// The members are the `[0]` recipient process, the `[1]` monitored
/// BACnetObjectPropertyReference (which has no device member), the `[2]`
/// form, the `[3]` time remaining and the optional `[4]` REAL increment. The
/// next list element opens with `[0]`, so a `[4]` that follows can only be
/// this element's increment.
pub fn decode_cov_subscription(
    data: &[u8],
    offset: usize,
) -> Result<(BACnetCOVSubscription, usize), Error> {
    let what = "BACnetCOVSubscription";
    let (recipient, pos) = decode_recipient_process(data, offset, what)?;
    let pos = expect_opening(data, pos, 1, what)?;
    let (reference, pos) = tags::extract_context_value(data, pos, 1)?;
    let monitored_property_reference = decode_object_property_reference(reference)?;
    let (issue_confirmed_notifications, pos) = decode_ctx_boolean(data, pos, 2, what)?;
    let (time_remaining, pos) = decode_ctx_u32(data, pos, 3, what)?;
    let (cov_increment, pos) = if next_is_primitive_context(data, pos, 4)? {
        let (increment, end) = decode_ctx_real(data, pos, 4, what)?;
        (Some(increment), end)
    } else {
        (None, pos)
    };
    Ok((
        BACnetCOVSubscription {
            recipient,
            monitored_property_reference,
            issue_confirmed_notifications,
            time_remaining,
            cov_increment,
        },
        pos,
    ))
}

/// Decode one bare `BACnetCOVMultipleSubscription` at `offset`; returns it
/// and the offset past its closing `[4]` tag, in the layout
/// [`encode_cov_multiple_subscription`] writes. Each nested list holds at
/// most `MAX_FRAMED_ITEMS` entries.
pub fn decode_cov_multiple_subscription(
    data: &[u8],
    offset: usize,
) -> Result<(BACnetCOVMultipleSubscription, usize), Error> {
    let what = "BACnetCOVMultipleSubscription";
    let (recipient, pos) = decode_recipient_process(data, offset, what)?;
    let (issue_confirmed_notifications, pos) = decode_ctx_boolean(data, pos, 1, what)?;
    let (time_remaining, pos) = decode_ctx_u32(data, pos, 2, what)?;
    let (max_notification_delay, pos) = decode_ctx_u32(data, pos, 3, what)?;
    let mut pos = expect_opening(data, pos, 4, what)?;
    let mut specifications = Vec::new();
    while !is_closing(data, pos, 4)? {
        if specifications.len() >= MAX_FRAMED_ITEMS {
            return Err(Error::decoding(
                pos,
                format!("{what}: specification count exceeds limit"),
            ));
        }
        let (specification, end) = decode_specification(data, pos, what)?;
        specifications.push(specification);
        pos = end;
    }
    let pos = expect_closing(data, pos, 4, what)?;
    Ok((
        BACnetCOVMultipleSubscription {
            recipient,
            issue_confirmed_notifications,
            time_remaining,
            max_notification_delay,
            list_of_cov_subscription_specifications: specifications,
        },
        pos,
    ))
}

/// The `[0]` monitored object identifier, then the `[1]` list of COV
/// references.
fn decode_specification(
    data: &[u8],
    offset: usize,
    what: &str,
) -> Result<(BACnetCOVSubscriptionSpecification, usize), Error> {
    let (tag, pos) = tags::decode_tag(data, offset)?;
    if !tag.is_context(0) || tag.length != 4 {
        return Err(Error::decoding(
            offset,
            format!("{what}: expected [0] monitored-object-identifier (4 octets)"),
        ));
    }
    let end = pos + 4;
    if end > data.len() {
        return Err(Error::buffer_too_short(end, data.len()));
    }
    let monitored_object_identifier = ObjectIdentifier::decode(&data[pos..end])?;
    let mut pos = expect_opening(data, end, 1, what)?;
    let mut references = Vec::new();
    while !is_closing(data, pos, 1)? {
        if references.len() >= MAX_FRAMED_ITEMS {
            return Err(Error::decoding(
                pos,
                format!("{what}: COV reference count exceeds limit"),
            ));
        }
        let (reference, end) = decode_cov_reference(data, pos, what)?;
        references.push(reference);
        pos = end;
    }
    Ok((
        BACnetCOVSubscriptionSpecification {
            monitored_object_identifier,
            list_of_cov_references: references,
        },
        expect_closing(data, pos, 1, what)?,
    ))
}

/// The `[0]` BACnetPropertyReference (`[0]` identifier and optional `[1]`
/// index), the optional `[1]` REAL increment and the `[2]` timestamped flag.
fn decode_cov_reference(
    data: &[u8],
    offset: usize,
    what: &str,
) -> Result<(BACnetCOVReference, usize), Error> {
    let pos = expect_opening(data, offset, 0, what)?;
    let (property_identifier, pos) = decode_ctx_u32(data, pos, 0, what)?;
    let (property_array_index, pos) = if next_is_primitive_context(data, pos, 1)? {
        let (index, end) = decode_ctx_u32(data, pos, 1, what)?;
        (Some(index), end)
    } else {
        (None, pos)
    };
    let pos = expect_closing(data, pos, 0, what)?;
    let (cov_increment, pos) = if next_is_primitive_context(data, pos, 1)? {
        let (increment, end) = decode_ctx_real(data, pos, 1, what)?;
        (Some(increment), end)
    } else {
        (None, pos)
    };
    let (timestamped, pos) = decode_ctx_boolean(data, pos, 2, what)?;
    Ok((
        BACnetCOVReference {
            property_identifier: PropertyIdentifier::from_raw(property_identifier),
            property_array_index,
            cov_increment,
            timestamped,
        },
        pos,
    ))
}

/// The `[0]` BACnetRecipientProcess: the `[0]` recipient CHOICE and the `[1]`
/// process identifier.
fn decode_recipient_process(
    data: &[u8],
    offset: usize,
    what: &str,
) -> Result<(BACnetRecipientProcess, usize), Error> {
    let pos = expect_opening(data, offset, 0, what)?;
    let pos = expect_opening(data, pos, 0, what)?;
    let (recipient, pos) = decode_recipient(data, pos)?;
    let pos = expect_closing(data, pos, 0, what)?;
    let (process_identifier, pos) = decode_ctx_u32(data, pos, 1, what)?;
    let pos = expect_closing(data, pos, 0, what)?;
    Ok((
        BACnetRecipientProcess {
            recipient,
            process_identifier,
        },
        pos,
    ))
}

fn decode_ctx_u32(data: &[u8], offset: usize, tag: u8, what: &str) -> Result<(u32, usize), Error> {
    let (value, end) = decode_ctx_unsigned(data, offset, tag, what)?;
    let value = u32::try_from(value)
        .map_err(|_| Error::decoding(offset, format!("{what}: [{tag}] exceeds Unsigned32")))?;
    Ok((value, end))
}

/// A context-tagged BOOLEAN has one contents octet, 0 or 1 (Clause 20.2.3).
fn decode_ctx_boolean(
    data: &[u8],
    offset: usize,
    tag: u8,
    what: &str,
) -> Result<(bool, usize), Error> {
    let (t, pos) = tags::decode_tag(data, offset)?;
    if !t.is_context(tag) || t.length != 1 {
        return Err(Error::decoding(
            offset,
            format!("{what}: expected context tag [{tag}] BOOLEAN (1 octet)"),
        ));
    }
    match data.get(pos) {
        Some(0) => Ok((false, pos + 1)),
        Some(1) => Ok((true, pos + 1)),
        Some(_) => Err(Error::decoding(
            pos,
            format!("{what}: [{tag}] BOOLEAN contents must be 0 or 1"),
        )),
        None => Err(Error::buffer_too_short(pos + 1, data.len())),
    }
}

/// Whether a primitive context tag `tag` starts at `offset`; `false` at the
/// end of the data.
fn next_is_primitive_context(data: &[u8], offset: usize, tag: u8) -> Result<bool, Error> {
    if offset >= data.len() {
        return Ok(false);
    }
    Ok(tags::decode_tag(data, offset)?.0.is_context(tag))
}

/// Whether closing tag `tag` starts at `offset`. A list that runs off the end
/// of the data is truncated.
fn is_closing(data: &[u8], offset: usize, tag: u8) -> Result<bool, Error> {
    if offset >= data.len() {
        return Err(Error::buffer_too_short(offset + 1, data.len()));
    }
    Ok(tags::decode_tag(data, offset)?.0.is_closing_tag(tag))
}
