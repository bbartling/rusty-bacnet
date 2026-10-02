//! Reaching the B/IP transport behind a transport that may carry BACnet/IP.

use bacnet_types::error::Error;

use super::BipTransport;

/// A transport that may carry BACnet/IP, and so can lend its [`BipTransport`].
///
/// BBMD management (Annex J) and the B/IP counters only exist on a
/// [`BipTransport`]. This trait lets code that holds some other transport type
/// reach them when the data link underneath is B/IP. `BACnetClient`'s BBMD
/// helpers take any transport with it, so the same calls work on a client over
/// [`BipTransport`] and on one over [`AnyTransport`](crate::any::AnyTransport).
///
/// A wrapper transport, such as a decorator around a `BipTransport`, can
/// implement it by delegating to the transport it wraps.
pub trait AsBip {
    /// The B/IP transport underneath this one.
    ///
    /// # Errors
    ///
    /// [`Error::UnsupportedTransport`] naming this transport's data link when
    /// it is not BACnet/IP.
    fn as_bip(&self) -> Result<&BipTransport, Error>;
}

impl AsBip for BipTransport {
    /// Always this transport.
    fn as_bip(&self) -> Result<&BipTransport, Error> {
        Ok(self)
    }
}
