use bacnet_encoding::tags;
use bacnet_types::enums::{PropertyIdentifier, RejectReason};
use bacnet_types::error::Error;
use bacnet_types::primitives::{Date, Time};
use bytes::BytesMut;

pub(super) fn reject(reason: RejectReason, _message: &'static str) -> Error {
    Error::Reject {
        reason: reason.to_raw(),
    }
}

fn property_identifier_is_forbidden(property_identifier: PropertyIdentifier) -> bool {
    matches!(
        property_identifier,
        PropertyIdentifier::ALL | PropertyIdentifier::OPTIONAL | PropertyIdentifier::REQUIRED
    )
}

pub(super) fn validate_property_identifier(
    property_identifier: PropertyIdentifier,
    field: &str,
) -> Result<(), Error> {
    if property_identifier_is_forbidden(property_identifier) {
        return Err(Error::Encoding(format!(
            "{field} cannot be ALL, OPTIONAL, or REQUIRED"
        )));
    }
    Ok(())
}

pub(super) fn validate_decoded_property_identifier(
    property_identifier: PropertyIdentifier,
    _field: &str,
) -> Result<(), Error> {
    if property_identifier_is_forbidden(property_identifier) {
        return Err(reject(
            RejectReason::PARAMETER_OUT_OF_RANGE,
            "property identifier is forbidden in COV Multiple",
        ));
    }
    Ok(())
}

pub(super) fn validate_raw_property_value(value: &[u8]) -> Result<(), Error> {
    if value.is_empty() {
        return Err(Error::Encoding(
            "COVNotificationMultiple property value must not be empty".into(),
        ));
    }
    let mut framed = BytesMut::new();
    tags::encode_opening_tag(&mut framed, 2);
    let content_start = framed.len();
    framed.extend_from_slice(value);
    tags::encode_closing_tag(&mut framed, 2);
    let (_, end) = tags::extract_context_value(&framed, content_start, 2)
        .map_err(|error| Error::Encoding(format!("invalid property value: {error}")))?;
    if end != framed.len() {
        return Err(Error::Encoding(
            "COVNotificationMultiple property value has unbalanced tags".into(),
        ));
    }
    Ok(())
}

pub(super) fn decode_date_time(
    data: &[u8],
    offset: usize,
    context_tag: u8,
) -> Result<((Date, Time), usize), Error> {
    let (opening, mut pos) = tags::decode_tag(data, offset)?;
    if !opening.is_opening_tag(context_tag) {
        return Err(reject(
            RejectReason::INVALID_TAG,
            "invalid DateTime opening tag",
        ));
    }

    let (date_tag, content_start) = tags::decode_tag(data, pos)?;
    if date_tag.class != tags::TagClass::Application
        || date_tag.number != tags::app_tag::DATE
        || date_tag.length != 4
    {
        return Err(reject(
            RejectReason::INVALID_DATA_ENCODING,
            "invalid DateTime Date",
        ));
    }
    let content_end = content_start.checked_add(4).ok_or_else(|| {
        reject(
            RejectReason::INVALID_DATA_ENCODING,
            "DateTime Date length overflow",
        )
    })?;
    let date = Date::decode(data.get(content_start..content_end).ok_or_else(|| {
        reject(
            RejectReason::INVALID_DATA_ENCODING,
            "truncated DateTime Date",
        )
    })?)
    .map_err(|_| reject(RejectReason::INVALID_DATA_ENCODING, "invalid DateTime Date"))?;
    pos = content_end;

    let (time_tag, content_start) = tags::decode_tag(data, pos)?;
    if time_tag.class != tags::TagClass::Application
        || time_tag.number != tags::app_tag::TIME
        || time_tag.length != 4
    {
        return Err(reject(
            RejectReason::INVALID_DATA_ENCODING,
            "invalid DateTime Time",
        ));
    }
    let content_end = content_start.checked_add(4).ok_or_else(|| {
        reject(
            RejectReason::INVALID_DATA_ENCODING,
            "DateTime Time length overflow",
        )
    })?;
    let time = Time::decode(data.get(content_start..content_end).ok_or_else(|| {
        reject(
            RejectReason::INVALID_DATA_ENCODING,
            "truncated DateTime Time",
        )
    })?)
    .map_err(|_| reject(RejectReason::INVALID_DATA_ENCODING, "invalid DateTime Time"))?;
    pos = content_end;

    let (closing, end) = tags::decode_tag(data, pos)?;
    if !closing.is_closing_tag(context_tag) {
        return Err(reject(
            RejectReason::INVALID_TAG,
            "invalid DateTime closing tag",
        ));
    }
    Ok(((date, time), end))
}
