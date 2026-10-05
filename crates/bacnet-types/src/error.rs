//! BACnet error types.
//!
//! Provides the top-level [`Error`] type used throughout the library,
//! covering protocol errors, encoding/decoding failures, transport issues,
//! and timeouts.

#[cfg(not(feature = "std"))]
use alloc::{boxed::Box, format, string::String, vec::Vec};
#[cfg(feature = "std")]
use std::time::Duration;

use crate::constructed::BACnetObjectPropertyReference;
use crate::data_link::DataLink;
use crate::enums::{ErrorClass, ErrorCode, PropertyIdentifier, RejectReason};

fn format_protocol_error(class: u32, code: u32) -> String {
    let class_name = ErrorClass::ALL_NAMED
        .iter()
        .find(|(_, v)| v.to_raw() as u32 == class)
        .map(|(n, _)| n.to_lowercase().replace('_', "-"));
    let code_name = ErrorCode::ALL_NAMED
        .iter()
        .find(|(_, v)| v.to_raw() as u32 == code)
        .map(|(n, _)| n.to_lowercase().replace('_', "-"));

    match (class_name, code_name) {
        (Some(cn), Some(co)) => format!("BACnet error: {cn} / {co}"),
        (Some(cn), None) => format!("BACnet error: {cn} / code={code}"),
        (None, Some(co)) => format!("BACnet error: class={class} / {co}"),
        (None, None) => format!("BACnet error: class={class} / code={code}"),
    }
}

/// Top-level error type for the BACnet library.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// BACnet protocol error response (Clause 20.1.7).
    #[error("{}", format_protocol_error(*.class, *.code))]
    Protocol {
        /// Error class value.
        class: u32,
        /// Error code value.
        code: u32,
    },

    /// BACnet error response whose Clause 21 production carries more than the
    /// class and code: ChangeList-Error, CreateObject-Error,
    /// WritePropertyMultiple-Error, SubscribeCOVPropertyMultiple-Error,
    /// ConfirmedPrivateTransfer-Error or VTClose-Error. `detail` holds the
    /// extra fields; a body whose optional fields are all absent is reported
    /// as [`Error::Protocol`].
    #[error("{}, {detail}", format_protocol_error(*.class, *.code))]
    Structured {
        /// Error class value.
        class: u32,
        /// Error code value.
        code: u32,
        /// The production's fields after the class and code. Boxed so the
        /// rare structured error does not widen every `Result<_, Error>`.
        detail: Box<ErrorDetail>,
    },

    /// BACnet reject PDU (Clause 20.1.5).
    #[error("BACnet reject: reason={reason}")]
    Reject {
        /// Reject reason value.
        reason: u8,
    },

    /// BACnet abort PDU (Clause 20.1.6).
    #[error("BACnet abort: reason={reason}")]
    Abort {
        /// Abort reason value.
        reason: u8,
    },

    /// A router reported that the active message was too long for a routed path.
    #[error("message is too long for routed path to DNET {dnet}")]
    RoutedPathTooLong {
        /// Destination network rejected by the router.
        dnet: u16,
    },

    /// The client cannot safely allocate state for another routed path.
    #[error("routed path state capacity of {capacity} entries is exhausted")]
    RoutedPathCapacityExceeded {
        /// Maximum number of immediate-router/DNET path entries retained.
        capacity: usize,
    },

    /// The endpoint's transport cannot carry the requested operation, such as
    /// a BBMD management request through a data link other than BACnet/IP.
    /// Nothing was sent.
    #[error("operation requires {required}; this transport is {actual}")]
    UnsupportedTransport {
        /// Data link the operation needs.
        required: DataLink,
        /// Data link the endpoint's transport carries.
        actual: DataLink,
    },

    /// Error encoding a PDU.
    #[error("encoding error: {0}")]
    Encoding(String),

    /// Error decoding received data.
    #[error("decoding error at offset {offset}: {message}")]
    Decoding {
        /// Byte offset where the error occurred.
        offset: usize,
        /// Which kind of fault the decoder found.
        kind: DecodingKind,
        /// Description of what went wrong.
        message: String,
    },

    /// Transport-level I/O error.
    #[cfg(feature = "std")]
    #[error("transport error: {0}")]
    Transport(#[from] std::io::Error),

    /// Request timed out.
    #[cfg(feature = "std")]
    #[error("request timed out after {0:?}")]
    Timeout(Duration),

    /// Segmentation assembly error.
    #[error("segmentation error: {0}")]
    Segmentation(String),

    /// Buffer too short for the expected data.
    #[error("buffer too short: need {need} bytes, have {have}")]
    BufferTooShort {
        /// Minimum bytes needed.
        need: usize,
        /// Bytes actually available.
        have: usize,
    },

    /// Value out of valid range.
    #[error("value out of range: {0}")]
    OutOfRange(String),
}

/// Which fault a decoder found in the data it refused, so a responder can
/// name it (#1446). [`Error::reject_reason`] gives the Clause 18.9 Reject
/// reason each kind draws when the data was a confirmed request.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum DecodingKind {
    /// A fault the other kinds don't name: contents that don't fit their
    /// type or range, a wrong length, a reserved choice, too many items, or
    /// nesting too deep.
    Malformed,
    /// A tag that doesn't fit where it stands: another number, class or form
    /// than the member there needs, a closing tag that matches no opening
    /// one, or a tag header that is itself malformed.
    InvalidTag,
    /// The data ends, or the enclosing frame closes, where a required member
    /// or a frame's closing tag is due: a member is missing.
    Missing,
    /// Octets are left after the last member of a value that must fill its
    /// input: arguments beyond those the production has.
    Trailing,
}

impl DecodingKind {
    /// The Clause 18.9 Reject reason that names this fault in a confirmed
    /// request: OTHER, INVALID_TAG, MISSING_REQUIRED_PARAMETER or
    /// TOO_MANY_ARGUMENTS.
    pub fn reject_reason(self) -> RejectReason {
        match self {
            Self::Malformed => RejectReason::OTHER,
            Self::InvalidTag => RejectReason::INVALID_TAG,
            Self::Missing => RejectReason::MISSING_REQUIRED_PARAMETER,
            Self::Trailing => RejectReason::TOO_MANY_ARGUMENTS,
        }
    }
}

/// The fields a Clause 21 error production adds to the error class and code,
/// one variant per shape. The service the error answers names the production.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ErrorDetail {
    /// ChangeList-Error (AddListElement, RemoveListElement; Clauses 15.1.1.3
    /// and 15.2.1.3) and CreateObject-Error (Clause 15.3.1.3): the 1-based
    /// position of the refused element in the request's List of Elements or
    /// List of Initial Values, or 0 when the failure is not about one element.
    /// An object refusing one element of a list-valued write uses it too, for
    /// that element's position in the list it was given; the server's list
    /// handler turns that into the request's position.
    FirstFailedElementNumber(u32),
    /// WritePropertyMultiple-Error (Clause 15.10.1.3): the object, property
    /// and array index of the first write that failed.
    FirstFailedWriteAttempt(BACnetObjectPropertyReference),
    /// SubscribeCOVPropertyMultiple-Error (Clause 13.16.1.3) in its
    /// first-failed-subscription form: the monitored object and the property
    /// reference of the COV reference that failed. The other form, a general
    /// error, has no detail.
    FirstFailedSubscription(BACnetObjectPropertyReference),
    /// ConfirmedPrivateTransfer-Error (Clause 16.2.1.3): the vendor and
    /// service the error answers, and any vendor-defined error parameters.
    PrivateTransfer {
        /// Vendor identifier of the private service.
        vendor_id: u32,
        /// Vendor-defined service number.
        service_number: u32,
        /// Error parameters as encoded inside their context tag 3 frame,
        /// opaque to the stack; `None` when absent.
        error_parameters: Option<Vec<u8>>,
    },
    /// VTClose-Error (Clause 17.3.1.3) with its list present: the
    /// requester's local identifiers of the VT sessions that could not be
    /// closed. Without the list the error has no detail.
    VtSessionIdentifiers(Vec<u8>),
}

impl core::fmt::Display for ErrorDetail {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        fn reference(
            f: &mut core::fmt::Formatter<'_>,
            what: &str,
            reference: &BACnetObjectPropertyReference,
        ) -> core::fmt::Result {
            write!(
                f,
                "{what} {} {}",
                reference.object_identifier,
                PropertyIdentifier::from_raw(reference.property_identifier)
            )?;
            match reference.property_array_index {
                Some(index) => write!(f, "[{index}]"),
                None => Ok(()),
            }
        }
        match self {
            Self::FirstFailedElementNumber(number) => write!(f, "first failed element {number}"),
            Self::FirstFailedWriteAttempt(attempt) => {
                reference(f, "first failed write attempt", attempt)
            }
            Self::FirstFailedSubscription(subscription) => {
                reference(f, "first failed subscription", subscription)
            }
            Self::PrivateTransfer {
                vendor_id,
                service_number,
                error_parameters,
            } => {
                write!(f, "vendor {vendor_id} service {service_number}")?;
                match error_parameters {
                    Some(parameters) => {
                        write!(f, ", {} octets of error parameters", parameters.len())
                    }
                    None => Ok(()),
                }
            }
            Self::VtSessionIdentifiers(sessions) => {
                f.write_str("VT sessions not closed:")?;
                for session in sessions {
                    write!(f, " {session}")?;
                }
                Ok(())
            }
        }
    }
}

/// Convenience alias for `Result<T, Error>`.
pub type Result<T> = core::result::Result<T, Error>;

impl Error {
    /// The error an Error PDU reports: [`Error::Structured`] when its body
    /// carried a detail, [`Error::Protocol`] otherwise.
    pub fn protocol(class: u32, code: u32, detail: Option<ErrorDetail>) -> Self {
        match detail {
            Some(detail) => Self::Structured {
                class,
                code,
                detail: Box::new(detail),
            },
            None => Self::Protocol { class, code },
        }
    }

    /// Create a [`DecodingKind::Malformed`] decoding error at the given byte
    /// offset.
    pub fn decoding(offset: usize, message: impl Into<String>) -> Self {
        Self::decoding_kind(DecodingKind::Malformed, offset, message)
    }

    /// Create a decoding error of `kind` at the given byte offset.
    pub fn decoding_kind(kind: DecodingKind, offset: usize, message: impl Into<String>) -> Self {
        Self::Decoding {
            offset,
            kind,
            message: message.into(),
        }
    }

    /// Create a [`DecodingKind::InvalidTag`] decoding error: a tag at
    /// `offset` that doesn't fit there.
    pub fn invalid_tag(offset: usize, message: impl Into<String>) -> Self {
        Self::decoding_kind(DecodingKind::InvalidTag, offset, message)
    }

    /// Create a [`DecodingKind::Missing`] decoding error: a required member
    /// due at `offset` isn't there.
    pub fn missing(offset: usize, message: impl Into<String>) -> Self {
        Self::decoding_kind(DecodingKind::Missing, offset, message)
    }

    /// Create a [`DecodingKind::Trailing`] decoding error: octets from
    /// `offset` on that the value leaves unread.
    pub fn trailing(offset: usize, message: impl Into<String>) -> Self {
        Self::decoding_kind(DecodingKind::Trailing, offset, message)
    }

    /// The Reject reason a responder answers a confirmed request with when
    /// this error refused it as a syntax fault (Clauses 18.9 and 20.1.8):
    /// the reason itself for [`Error::Reject`], the kind's reason for
    /// [`Error::Decoding`] (see [`DecodingKind::reject_reason`]), and
    /// MISSING_REQUIRED_PARAMETER for [`Error::BufferTooShort`], a member cut
    /// short because the data ran out before it was complete. `None` for any
    /// other error, which isn't a syntax fault.
    pub fn reject_reason(&self) -> Option<RejectReason> {
        match self {
            Self::Reject { reason } => Some(RejectReason::from_raw(*reason)),
            Self::Decoding { kind, .. } => Some(kind.reject_reason()),
            Self::BufferTooShort { .. } => Some(RejectReason::MISSING_REQUIRED_PARAMETER),
            _ => None,
        }
    }

    /// This error, met decoding a confirmed request's own parameters, as the
    /// [`Error::Reject`] a responder answers with: the
    /// [`reject_reason`](Self::reject_reason) when it is a syntax fault, the
    /// error unchanged otherwise.
    ///
    /// A responder converts only the request's decode with this. A decoding
    /// error met later, once the service has started to run, is no reason to
    /// reject the request (Clause 20.1.8), so it stays as it is.
    pub fn into_request_reject(self) -> Self {
        match self.reject_reason() {
            Some(reason) => Self::Reject {
                reason: reason.to_raw(),
            },
            None => self,
        }
    }

    /// Create a buffer-too-short error.
    pub fn buffer_too_short(need: usize, have: usize) -> Self {
        Self::BufferTooShort { need, have }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn protocol_error_display() {
        let err = Error::Protocol { class: 2, code: 31 };
        assert!(err.to_string().contains("property"));
        assert!(err.to_string().contains("unknown-object"));

        // Unknown class/code falls back to numeric
        let err2 = Error::Protocol {
            class: 999,
            code: 999,
        };
        assert!(err2.to_string().contains("class=999"));
        assert!(err2.to_string().contains("code=999"));
    }

    #[test]
    fn structured_error_display_names_the_detail() {
        use crate::enums::ObjectType;
        use crate::primitives::ObjectIdentifier;

        let reference = |index| BACnetObjectPropertyReference {
            object_identifier: ObjectIdentifier::new(ObjectType::ANALOG_VALUE, 7).unwrap(),
            property_identifier: PropertyIdentifier::PRESENT_VALUE.to_raw(),
            property_array_index: index,
        };
        let private_transfer = |error_parameters| ErrorDetail::PrivateTransfer {
            vendor_id: 555,
            service_number: 7,
            error_parameters,
        };
        for (class, code, detail, expected) in [
            (
                5,
                81,
                ErrorDetail::FirstFailedElementNumber(2),
                "BACnet error: services / list-element-not-found, first failed element 2",
            ),
            (
                2,
                40,
                ErrorDetail::FirstFailedWriteAttempt(reference(Some(3))),
                "BACnet error: property / write-access-denied, \
                 first failed write attempt ANALOG_VALUE,7 PRESENT_VALUE[3]",
            ),
            (
                2,
                44,
                ErrorDetail::FirstFailedSubscription(reference(None)),
                "BACnet error: property / not-cov-property, \
                 first failed subscription ANALOG_VALUE,7 PRESENT_VALUE",
            ),
            (
                5,
                0,
                private_transfer(Some(vec![0x21, 1])),
                "BACnet error: services / other, vendor 555 service 7, \
                 2 octets of error parameters",
            ),
            (
                5,
                0,
                private_transfer(None),
                "BACnet error: services / other, vendor 555 service 7",
            ),
            (
                5,
                39,
                ErrorDetail::VtSessionIdentifiers(vec![1, 4]),
                "BACnet error: services / vt-session-termination-failure, \
                 VT sessions not closed: 1 4",
            ),
        ] {
            assert_eq!(
                Error::protocol(class, code, Some(detail)).to_string(),
                expected
            );
        }
        assert!(matches!(
            Error::protocol(2, 31, None),
            Error::Protocol { class: 2, code: 31 }
        ));
    }

    #[test]
    fn decoding_error_display() {
        let err = Error::decoding(42, "unexpected tag");
        assert!(err.to_string().contains("offset 42"));
        assert!(err.to_string().contains("unexpected tag"));
    }

    #[test]
    fn syntax_faults_name_their_reject_reasons() {
        for (error, reason) in [
            (Error::decoding(1, "bad"), RejectReason::OTHER),
            (Error::invalid_tag(1, "tag"), RejectReason::INVALID_TAG),
            (
                Error::missing(1, "gone"),
                RejectReason::MISSING_REQUIRED_PARAMETER,
            ),
            (Error::trailing(1, "more"), RejectReason::TOO_MANY_ARGUMENTS),
            (
                Error::buffer_too_short(9, 4),
                RejectReason::MISSING_REQUIRED_PARAMETER,
            ),
            (
                Error::Reject { reason: 8 },
                RejectReason::UNDEFINED_ENUMERATION,
            ),
        ] {
            assert_eq!(error.reject_reason(), Some(reason), "{error}");
        }
        for error in [
            Error::Protocol { class: 5, code: 0 },
            Error::Encoding("x".into()),
            Error::OutOfRange("x".into()),
            Error::Abort { reason: 1 },
        ] {
            assert_eq!(error.reject_reason(), None, "{error}");
        }
        // A request's decode error becomes its Reject; any other error stays.
        assert!(matches!(
            Error::trailing(3, "more").into_request_reject(),
            Error::Reject { reason } if reason == RejectReason::TOO_MANY_ARGUMENTS.to_raw()
        ));
        assert!(matches!(
            Error::OutOfRange("x".into()).into_request_reject(),
            Error::OutOfRange(_)
        ));
        // The kind doesn't show in the message.
        assert_eq!(
            Error::trailing(3, "two trailing byte(s)").to_string(),
            "decoding error at offset 3: two trailing byte(s)"
        );
    }

    #[test]
    fn buffer_too_short_display() {
        let err = Error::buffer_too_short(10, 3);
        assert!(err.to_string().contains("need 10"));
        assert!(err.to_string().contains("have 3"));
    }

    #[cfg(feature = "std")]
    #[test]
    fn timeout_error_display() {
        let err = Error::Timeout(Duration::from_secs(3));
        assert!(err.to_string().contains("3s"));
    }

    #[test]
    fn routed_path_too_long_display_preserves_dnet() {
        let err = Error::RoutedPathTooLong { dnet: 1234 };
        assert!(err.to_string().contains("1234"));
    }

    #[test]
    fn routed_path_capacity_display_preserves_bound() {
        let err = Error::RoutedPathCapacityExceeded { capacity: 256 };
        assert!(err.to_string().contains("256"));
    }

    #[test]
    fn unsupported_transport_display_names_both_data_links() {
        let err = Error::UnsupportedTransport {
            required: DataLink::Bip,
            actual: DataLink::Mstp,
        };
        assert_eq!(
            err.to_string(),
            "operation requires BACnet/IP; this transport is MS/TP"
        );
    }
}
