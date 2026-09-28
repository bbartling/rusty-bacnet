//! A synchronous packet-info syscall attempt inside Tokio writable readiness.
//!
//! No native pointer or pending overlapped operation survives a syscall attempt.
#![allow(unsafe_code)]

use super::link::SelectedLink;
use socket2::Socket;
use std::{io, net::SocketAddrV6};
use tokio::{io::Interest, net::UdpSocket};

pub(super) struct SelectedSender {
    #[cfg(windows)]
    function: windows_sys::Win32::Networking::WinSock::LPFN_WSASENDMSG,
}

impl SelectedSender {
    pub fn new(socket: &Socket) -> io::Result<Self> {
        #[cfg(windows)]
        {
            Ok(Self {
                function: windows_function(socket)?,
            })
        }
        #[cfg(unix)]
        {
            let _ = socket;
            Ok(Self {})
        }
        #[cfg(not(any(unix, windows)))]
        {
            let _ = socket;
            Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "IPv6 source selection unsupported",
            ))
        }
    }

    pub async fn send(
        &self,
        socket: &UdpSocket,
        bytes: &[u8],
        mut peer: SocketAddrV6,
        link: SelectedLink,
    ) -> io::Result<usize> {
        if peer.ip().is_unicast_link_local() || peer.ip().is_multicast() {
            peer.set_scope_id(link.index);
        }
        let count = socket
            .async_io(Interest::WRITABLE, || {
                self.try_send(socket, bytes, peer, link)
            })
            .await?;
        if count != bytes.len() {
            return Err(io::Error::new(
                io::ErrorKind::WriteZero,
                "partial IPv6 datagram send",
            ));
        }
        Ok(count)
    }

    #[cfg(unix)]
    fn try_send(
        &self,
        socket: &UdpSocket,
        bytes: &[u8],
        peer: SocketAddrV6,
        link: SelectedLink,
    ) -> io::Result<usize> {
        use std::{
            mem::{size_of, zeroed},
            os::fd::AsRawFd,
        };
        let destination = socket2::SockAddr::from(peer);
        let mut control = [0usize; 16];
        let mut iov = libc::iovec {
            iov_base: bytes.as_ptr().cast_mut().cast(),
            iov_len: bytes.len(),
        };
        // SAFETY: all-zero msghdr has null pointers/zero lengths. Every active
        // field below points to live aligned storage through synchronous sendmsg.
        let mut message: libc::msghdr = unsafe { zeroed() };
        message.msg_name = destination.as_ptr().cast_mut().cast();
        message.msg_namelen = destination.len();
        message.msg_iov = &mut iov;
        message.msg_iovlen = 1;
        message.msg_control = control.as_mut_ptr().cast();
        // SAFETY: the payload size is fixed and the aligned array is larger
        // than CMSG_SPACE on supported Unix targets. No memory escapes this call.
        let count = unsafe {
            let space = libc::CMSG_SPACE(size_of::<libc::in6_pktinfo>() as _) as usize;
            assert!(space <= size_of_val(&control));
            message.msg_controllen = space as _;
            let header = libc::CMSG_FIRSTHDR(&message);
            (*header).cmsg_level = libc::IPPROTO_IPV6;
            (*header).cmsg_type = libc::IPV6_PKTINFO;
            (*header).cmsg_len = libc::CMSG_LEN(size_of::<libc::in6_pktinfo>() as _) as _;
            std::ptr::write(
                libc::CMSG_DATA(header).cast::<libc::in6_pktinfo>(),
                libc::in6_pktinfo {
                    ipi6_addr: libc::in6_addr {
                        s6_addr: link.address.octets(),
                    },
                    ipi6_ifindex: link.index,
                },
            );
            libc::sendmsg(socket.as_raw_fd(), &message, 0)
        };
        if count < 0 {
            Err(io::Error::last_os_error())
        } else {
            Ok(count as usize)
        }
    }

    #[cfg(windows)]
    fn try_send(
        &self,
        udp_socket: &UdpSocket,
        bytes: &[u8],
        peer: SocketAddrV6,
        link: SelectedLink,
    ) -> io::Result<usize> {
        use std::{mem::size_of, os::windows::io::AsRawSocket};
        use windows_sys::Win32::Networking::WinSock::*;
        let function = self
            .function
            .ok_or_else(|| io::Error::new(io::ErrorKind::Unsupported, "WSASendMsg unavailable"))?;
        let destination = socket2::SockAddr::from(peer);
        let mut control = [0usize; 16];
        let align = |len: usize| len.next_multiple_of(size_of::<usize>());
        let offset = align(size_of::<CMSGHDR>());
        let length = offset + size_of::<IN6_PKTINFO>();
        let space = align(length);
        assert!(space <= size_of_val(&control));
        let mut info = IN6_PKTINFO::default();
        info.ipi6_addr.u.Byte = link.address.octets();
        info.ipi6_ifindex = link.index;
        // SAFETY: control is suitably aligned and both fixed-size writes are
        // within its checked capacity; header length includes the full payload.
        unsafe {
            std::ptr::write(
                control.as_mut_ptr().cast::<CMSGHDR>(),
                CMSGHDR {
                    cmsg_len: length,
                    cmsg_level: IPPROTO_IPV6,
                    cmsg_type: IPV6_PKTINFO,
                },
            );
            std::ptr::write(
                control
                    .as_mut_ptr()
                    .cast::<u8>()
                    .add(offset)
                    .cast::<IN6_PKTINFO>(),
                info,
            );
        }
        let mut data = WSABUF {
            len: u32::try_from(bytes.len())
                .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "datagram too large"))?,
            buf: bytes.as_ptr().cast_mut(),
        };
        let message = WSAMSG {
            name: destination.as_ptr().cast_mut().cast(),
            namelen: destination.len() as i32,
            lpBuffers: &mut data,
            dwBufferCount: 1,
            Control: WSABUF {
                len: space as u32,
                buf: control.as_mut_ptr().cast(),
            },
            dwFlags: 0,
        };
        let mut sent = 0;
        // SAFETY: null OVERLAPPED and callback request a synchronous attempt,
        // including on an overlapped-created socket. All message/payload pointers
        // remain live until it returns; WouldBlock is retried by Tokio readiness.
        let result = unsafe {
            function(
                udp_socket.as_raw_socket() as SOCKET,
                &message,
                0,
                &mut sent,
                std::ptr::null_mut(),
                None,
            )
        };
        if result == SOCKET_ERROR {
            Err(io::Error::from_raw_os_error(unsafe { WSAGetLastError() }))
        } else {
            Ok(sent as usize)
        }
    }

    #[cfg(not(any(unix, windows)))]
    fn try_send(
        &self,
        _: &UdpSocket,
        _: &[u8],
        _: SocketAddrV6,
        _: SelectedLink,
    ) -> io::Result<usize> {
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "IPv6 source selection unsupported",
        ))
    }
}

#[cfg(windows)]
fn windows_function(
    udp_socket: &Socket,
) -> io::Result<windows_sys::Win32::Networking::WinSock::LPFN_WSASENDMSG> {
    use std::{mem::size_of, os::windows::io::AsRawSocket};
    use windows_sys::Win32::Networking::WinSock::*;
    let mut function: LPFN_WSASENDMSG = None;
    let mut returned = 0;
    // SAFETY: synchronous extension lookup writes only the function-pointer
    // storage of the declared size. This socket owns the returned provider API.
    let result = unsafe {
        WSAIoctl(
            udp_socket.as_raw_socket() as SOCKET,
            SIO_GET_EXTENSION_FUNCTION_POINTER,
            (&WSAID_WSASENDMSG as *const windows_sys::core::GUID).cast(),
            size_of::<windows_sys::core::GUID>() as u32,
            (&mut function as *mut LPFN_WSASENDMSG).cast(),
            size_of::<LPFN_WSASENDMSG>() as u32,
            &mut returned,
            std::ptr::null_mut(),
            None,
        )
    };
    if result != 0 {
        return Err(io::Error::from_raw_os_error(unsafe { WSAGetLastError() }));
    }
    function
        .map(Some)
        .ok_or_else(|| io::Error::new(io::ErrorKind::Unsupported, "WSASendMsg unavailable"))
}
