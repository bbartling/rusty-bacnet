//! Encode and decode a Notification Forwarder's Subscribed_Recipients
//! elements (Clause 12.51.9, Clause 21 BACnetEventNotificationSubscription).
//!
//! Each element is a bare sequence of four context-tagged members, all
//! required: `[0]` wraps the recipient CHOICE, `[1]` is the process identifier
//! (Unsigned32), `[2]` the confirmation flag and `[3]` the minutes remaining.
//! The BACnetLIST concatenates elements with no wrapper, so the decoder reads
//! one element at `offset` and returns the offset just past it.
//!
//! A subscription's recipient decodes through [`decode_recipient`](super::decode_recipient)
//! and encodes through the same bound: an address MAC is at most
//! `BACnetAddress::MAX_MAC_LEN` octets (#1124, #1156).

use bacnet_types::constructed::BACnetEventNotificationSubscription;
use bacnet_types::error::Error;
use bytes::BytesMut;

use crate::{primitives, tags};

use super::cov_subscription::{decode_ctx_boolean, decode_ctx_u32};
use super::recipient::{check_encoded_recipient, write_recipient};
use super::{decode_recipient, expect_closing, expect_opening};

/// Encode one bare `BACnetEventNotificationSubscription` sequence. A
/// recipient MAC past `BACnetAddress::MAX_MAC_LEN` octets is an error,
/// returned before `buf` changes.
pub fn encode_event_notification_subscription(
    buf: &mut BytesMut,
    subscription: &BACnetEventNotificationSubscription,
) -> Result<(), Error> {
    check_encoded_recipient(&subscription.recipient)?;
    write_subscription(buf, subscription);
    Ok(())
}

/// Encode a `BACnetLIST of BACnetEventNotificationSubscription` in slice
/// order. Every recipient is checked before `buf` changes, so a refused list
/// writes nothing.
pub fn encode_event_notification_subscription_list(
    buf: &mut BytesMut,
    subscriptions: &[BACnetEventNotificationSubscription],
) -> Result<(), Error> {
    for subscription in subscriptions {
        check_encoded_recipient(&subscription.recipient)?;
    }
    for subscription in subscriptions {
        write_subscription(buf, subscription);
    }
    Ok(())
}

/// Write a subscription whose recipient has passed [`check_encoded_recipient`].
fn write_subscription(buf: &mut BytesMut, subscription: &BACnetEventNotificationSubscription) {
    tags::encode_opening_tag(buf, 0);
    write_recipient(buf, &subscription.recipient);
    tags::encode_closing_tag(buf, 0);
    primitives::encode_ctx_unsigned(buf, 1, u64::from(subscription.process_identifier));
    primitives::encode_ctx_boolean(buf, 2, subscription.issue_confirmed_notifications);
    primitives::encode_ctx_unsigned(buf, 3, u64::from(subscription.time_remaining));
}

/// Decode one bare `BACnetEventNotificationSubscription` at `offset`; returns
/// it and the offset past its `[3]` member. A member that is missing, out of
/// order, or past its range (a process identifier or time remaining beyond
/// Unsigned32) is a decode error.
pub fn decode_event_notification_subscription(
    data: &[u8],
    offset: usize,
) -> Result<(BACnetEventNotificationSubscription, usize), Error> {
    let what = "BACnetEventNotificationSubscription";
    let pos = expect_opening(data, offset, 0, what)?;
    let (recipient, pos) = decode_recipient(data, pos)?;
    let pos = expect_closing(data, pos, 0, what)?;
    let (process_identifier, pos) = decode_ctx_u32(data, pos, 1, what)?;
    let (issue_confirmed_notifications, pos) = decode_ctx_boolean(data, pos, 2, what)?;
    let (time_remaining, pos) = decode_ctx_u32(data, pos, 3, what)?;
    Ok((
        BACnetEventNotificationSubscription {
            recipient,
            process_identifier,
            issue_confirmed_notifications,
            time_remaining,
        },
        pos,
    ))
}
