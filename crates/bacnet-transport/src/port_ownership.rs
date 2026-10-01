//! Exclusive ownership of an unshared UDP port, the same on every OS.

use std::io;

/// Keep an unshared socket's port to itself. Call it before `bind`.
///
/// On Unix a socket without SO_REUSEADDR already owns its port: nothing else
/// can bind that port, on any address, while it is open. Windows lets another
/// socket bind a more specific address on the same port (127.0.0.1:P beside a
/// wildcard 0.0.0.0:P), and that socket then receives the unicast sent to it,
/// so an ephemeral B/IP or B/IPv6 port was neither private nor reliably ours.
/// SO_EXCLUSIVEADDRUSE refuses every other bind to the port, as Unix does.
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
/// Unix already gives a socket without SO_REUSEADDR sole use of its port.
#[cfg(not(windows))]
pub(crate) fn claim_exclusive(_socket: &socket2::Socket) -> io::Result<()> {
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::net::{Ipv4Addr, SocketAddr, UdpSocket};

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
