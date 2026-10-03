//! The work and byte limits every read service shares: ReadProperty,
//! ReadPropertyMultiple, ReadRange and the server's local read.
use super::*;

/// Why a bounded read produced no answer: a service error the requester sees,
/// or a work or byte limit the request would pass.
#[derive(Debug)]
pub(crate) enum ReadFailure {
    Service(Error),
    Work,
    Bytes,
}

impl ReadFailure {
    /// The error of a read made with no work or byte limit, which only a
    /// service error can fail.
    pub(super) fn unlimited(self) -> Error {
        match self {
            Self::Service(error) => error,
            Self::Work | Self::Bytes => unreachable!("a read with no limit ran past one"),
        }
    }
}

/// The result rows one read request has expanded, counted against its work
/// limit. A Group's Present_Value charges each member row to the request that
/// reads it (#1172), so several Groups in one request share the one limit.
pub(super) struct Work {
    used: usize,
    limit: usize,
}

impl Work {
    pub(super) fn new(limit: usize) -> Self {
        Self { used: 0, limit }
    }

    /// Count one more row, failing once the request would pass its limit.
    pub(super) fn charge(&mut self) -> Result<(), ReadFailure> {
        self.used = self
            .used
            .checked_add(1)
            .filter(|&n| n <= self.limit)
            .ok_or(ReadFailure::Work)?;
        Ok(())
    }
}
