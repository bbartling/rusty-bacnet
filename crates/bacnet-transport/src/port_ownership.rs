//! Keeping an unshared UDP port to its socket, as far as each OS allows.
//!
//! A B/IP or B/IPv6 socket on an ephemeral port binds the wildcard address
//! without SO_REUSEADDR (#892). How private that leaves the port depends on
//! the OS:
//!
//! - Linux refuses any other bind to the port, whatever options it sets.
//! - Windows lets another socket bind a more specific address on the same port
//!   (127.0.0.1:P beside a wildcard 0.0.0.0:P) and take the unicast sent
//!   there, unless the first socket set SO_EXCLUSIVEADDRUSE, which this module
//!   does (#950).
//! - macOS and the other BSDs refuse a plain bind there, but a socket that sets
//!   SO_REUSEADDR itself may still bind the more specific address. They have
//!   no option to stop it, so that case remains.

use std::io;

/// Keep an unshared socket's port to itself. Call it before `bind`.
///
/// Sets SO_EXCLUSIVEADDRUSE, which refuses every other bind to the port while
/// this socket is open.
#[cfg(windows)]
#[allow(unsafe_code)]
pub(crate) fn claim_exclusive(socket: &socket2::Socket) -> io::Result<()> {
    use std::os::windows::io::AsRawSocket;
    use windows_sys::Win32::Networking::WinSock::{
        setsockopt, WSAGetLastError, SOCKET, SOL_SOCKET, SO_EXCLUSIVEADDRUSE,
    };

    let enabled: i32 = 1;
    // SAFETY: the socket handle is open for the call's duration, and the
    // option value points to a live BOOL (i32) of the length passed.
    let result = unsafe {
        setsockopt(
            socket.as_raw_socket() as SOCKET,
            SOL_SOCKET,
            SO_EXCLUSIVEADDRUSE,
            (&enabled as *const i32).cast(),
            std::mem::size_of::<i32>() as i32,
        )
    };
    if result == 0 {
        Ok(())
    } else {
        // SAFETY: reads the calling thread's last Winsock error; no arguments.
        Err(io::Error::from_raw_os_error(unsafe { WSAGetLastError() }))
    }
}

/// Keep an unshared socket's port to itself. Call it before `bind`.
///
/// Nothing to set: Linux already refuses other binds, and macOS and the BSDs
/// have no option for the SO_REUSEADDR case the module docs describe.
#[cfg(not(windows))]
pub(crate) fn claim_exclusive(_socket: &socket2::Socket) -> io::Result<()> {
    Ok(())
}

/// Whether a bind failed because another socket holds the port. Tests whose
/// configuration must name a port before the transport binds it probe for a
/// free one, and another process can take it in between (#1032); this is the
/// failure they retry on. An explicit B/IP or B/IPv6 port sets SO_REUSEADDR,
/// and Windows refuses that bind with `WSAEACCES` rather than
/// `WSAEADDRINUSE` when the holder did not share the port. Only an OS error
/// counts, so a transport's own `AddrInUse` (a VMAC collision) does not.
///
/// On macOS a holder bound to a specific address does not fail the wildcard
/// bind at all; as the module docs say, nothing there reports that case.
#[cfg(test)]
pub(crate) fn lost_to_another_socket(err: &io::Error) -> bool {
    err.raw_os_error().is_some()
        && (err.kind() == io::ErrorKind::AddrInUse
            || (cfg!(windows) && err.kind() == io::ErrorKind::PermissionDenied))
}

#[cfg(test)]
mod tests {
    use std::net::{Ipv4Addr, SocketAddr, UdpSocket};

    /// A plain bind of 127.0.0.1:P beside the claimed 0.0.0.0:P fails on
    /// every OS; on Windows only because of the claim.
    #[test]
    fn a_claimed_wildcard_port_refuses_a_specific_address_bind() {
        let socket =
            socket2::Socket::new(socket2::Domain::IPV4, socket2::Type::DGRAM, None).unwrap();
        super::claim_exclusive(&socket).unwrap();
        socket
            .bind(&SocketAddr::from((Ipv4Addr::UNSPECIFIED, 0)).into())
            .unwrap();
        let port = socket.local_addr().unwrap().as_socket().unwrap().port();
        assert!(UdpSocket::bind((Ipv4Addr::LOCALHOST, port)).is_err());
        drop(socket);
        // UDP has no TIME_WAIT: the port is free as soon as its owner closes.
        UdpSocket::bind((Ipv4Addr::LOCALHOST, port)).unwrap();
    }
}
