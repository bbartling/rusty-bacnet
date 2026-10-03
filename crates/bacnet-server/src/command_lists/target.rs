//! Making one write of a run, in this device or another, and saying how it
//! failed (#1264).
//!
//! A Channel reports the first failure of a distribution in its Reliability
//! (Clause 12.53.9), which names three kinds: the member's configuration, a
//! communication failure, and any other error. The runner sorts each failed
//! write into one of them:
//!
//! - configuration: the target's answer says the reference names nothing it
//!   has (UNKNOWN_OBJECT, UNKNOWN_PROPERTY, an array index or array access
//!   that doesn't fit) or that the property takes no value of this datatype
//!   (INVALID_DATA_TYPE, DATATYPE_NOT_SUPPORTED, or a Reject for an invalid
//!   parameter datatype). The Schedule reads a datatype refusal the same way.
//!   A value the Channel itself can't coerce is a configuration failure too
//!   (in `channel`).
//! - communication: a member in another device that couldn't be reached: no
//!   fresh binding, initiation disabled by DeviceCommunicationControl, or no
//!   answer to the first attempt or any retry.
//! - process: every other refusal (an Error with another code, a Reject for
//!   another reason, an Abort) and every write this server couldn't send.
//!
//! A Command keeps only whether each write succeeded, so the kind matters to
//! Channels alone.

use bacnet_objects::command::{CommandRun, WriteFailure};
use bacnet_types::constructed::BACnetActionCommand;
use bacnet_types::enums::{ErrorCode, RejectReason};
use bacnet_types::error::Error;
use bacnet_types::primitives::ObjectIdentifier;
use tracing::debug;

use super::RunHost;
use crate::server::RemoteWriteError;

/// A write that failed.
#[derive(Debug)]
pub(super) struct Failed {
    /// How it failed.
    pub(super) failure: WriteFailure,
    /// The target's answer, when it refused the write.
    pub(super) answer: Option<Error>,
}

/// Make `command` on behalf of `run`: in this device, or in `device` when it
/// names another one.
pub(super) async fn write<H: RunHost>(
    host: &H,
    run: &CommandRun,
    device: Option<ObjectIdentifier>,
    command: &BACnetActionCommand,
) -> Result<(), Failed> {
    let failed = match device {
        None => {
            let Err(error) = host.write(run, command).await else {
                return Ok(());
            };
            debug!(
                source = %run.source,
                target = %command.object_identifier,
                property = ?command.property_identifier,
                %error,
                "Write failed"
            );
            Failed {
                failure: refused(&error),
                answer: Some(error),
            }
        }
        Some(device) => {
            let Err(error) = host.write_remote(device, command).await else {
                return Ok(());
            };
            debug!(
                source = %run.source,
                %device,
                target = %command.object_identifier,
                property = ?command.property_identifier,
                %error,
                "Write to another device failed"
            );
            match error {
                RemoteWriteError::Refused(refusal) => {
                    let answer = Error::from(refusal);
                    Failed {
                        failure: refused(&answer),
                        answer: Some(answer),
                    }
                }
                other => Failed {
                    failure: unmade(other),
                    answer: None,
                },
            }
        }
    };
    Err(failed)
}

/// The error code `error` carries, if it's an Error answer.
fn code(error: &Error) -> Option<u32> {
    match error {
        Error::Protocol { code, .. } | Error::Structured { code, .. } => Some(*code),
        _ => None,
    }
}

/// Whether the target refused the write for the value's datatype: an Error
/// of INVALID_DATA_TYPE or a Reject for an invalid parameter datatype, the
/// two answers Clause 12.53.7 names for a NULL.
pub(super) fn refuses_datatype(error: &Error) -> bool {
    let invalid = u32::from(ErrorCode::INVALID_DATA_TYPE.to_raw());
    code(error) == Some(invalid)
        || matches!(error, Error::Reject { reason }
            if *reason == RejectReason::INVALID_PARAMETER_DATA_TYPE.to_raw())
}

/// How a write the target refused with `error` failed.
fn refused(error: &Error) -> WriteFailure {
    const CONFIGURATION: [ErrorCode; 5] = [
        ErrorCode::UNKNOWN_OBJECT,
        ErrorCode::UNKNOWN_PROPERTY,
        ErrorCode::INVALID_ARRAY_INDEX,
        ErrorCode::PROPERTY_IS_NOT_AN_ARRAY,
        ErrorCode::DATATYPE_NOT_SUPPORTED,
    ];
    let configuration = refuses_datatype(error)
        || code(error).is_some_and(|code| {
            CONFIGURATION
                .iter()
                .any(|known| u32::from(known.to_raw()) == code)
        });
    if configuration {
        WriteFailure::Configuration
    } else {
        WriteFailure::Process
    }
}

/// How a write in another device that got no answer, or was never sent,
/// failed.
fn unmade(error: RemoteWriteError) -> WriteFailure {
    match error {
        RemoteWriteError::Disabled | RemoteWriteError::Unbound | RemoteWriteError::Unanswered => {
            WriteFailure::Communication
        }
        RemoteWriteError::Refused(refusal) => refused(&Error::from(refusal)),
        RemoteWriteError::Unencodable
        | RemoteWriteError::TooLong
        | RemoteWriteError::NoInvokeId
        | RemoteWriteError::Stopping
        | RemoteWriteError::NoNetwork => WriteFailure::Process,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::server::Refusal;
    use bacnet_types::enums::{AbortReason, ErrorClass};

    fn error(code: ErrorCode) -> Error {
        Refusal::Error {
            class: ErrorClass::PROPERTY,
            code,
        }
        .into()
    }

    #[test]
    fn failures_sort_into_configuration_process_and_communication() {
        for code in [
            ErrorCode::UNKNOWN_OBJECT,
            ErrorCode::UNKNOWN_PROPERTY,
            ErrorCode::INVALID_ARRAY_INDEX,
            ErrorCode::PROPERTY_IS_NOT_AN_ARRAY,
            ErrorCode::INVALID_DATA_TYPE,
            ErrorCode::DATATYPE_NOT_SUPPORTED,
        ] {
            assert_eq!(
                refused(&error(code)),
                WriteFailure::Configuration,
                "{code:?}"
            );
        }
        let datatype = Refusal::Reject(RejectReason::INVALID_PARAMETER_DATA_TYPE);
        assert_eq!(refused(&datatype.into()), WriteFailure::Configuration);
        for answer in [
            error(ErrorCode::WRITE_ACCESS_DENIED),
            error(ErrorCode::VALUE_OUT_OF_RANGE),
            Refusal::Reject(RejectReason::OTHER).into(),
            Refusal::Abort(AbortReason::OTHER).into(),
        ] {
            assert_eq!(refused(&answer), WriteFailure::Process, "{answer:?}");
        }

        for silence in [
            RemoteWriteError::Disabled,
            RemoteWriteError::Unbound,
            RemoteWriteError::Unanswered,
        ] {
            assert_eq!(unmade(silence), WriteFailure::Communication);
        }
        for local in [
            RemoteWriteError::Unencodable,
            RemoteWriteError::TooLong,
            RemoteWriteError::NoInvokeId,
            RemoteWriteError::Stopping,
            RemoteWriteError::NoNetwork,
        ] {
            assert_eq!(unmade(local), WriteFailure::Process);
        }
    }

    #[test]
    fn only_an_invalid_datatype_error_or_reject_refuses_the_datatype() {
        assert!(refuses_datatype(&error(ErrorCode::INVALID_DATA_TYPE)));
        assert!(refuses_datatype(
            &Refusal::Reject(RejectReason::INVALID_PARAMETER_DATA_TYPE).into()
        ));
        assert!(!refuses_datatype(&error(ErrorCode::DATATYPE_NOT_SUPPORTED)));
        assert!(!refuses_datatype(
            &Refusal::Reject(RejectReason::OTHER).into()
        ));
    }
}
