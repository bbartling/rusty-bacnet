//! Independent OS packet-info oracle, used only on an explicit isolated link.
#![allow(unsafe_code)]

use std::{
    io,
    mem::{size_of, zeroed},
    net::{Ipv6Addr, SocketAddrV6},
    os::fd::AsRawFd,
};
use tokio::{io::Interest, net::UdpSocket};

#[derive(Debug)]
pub(super) struct Frame {
    pub bytes: Vec<u8>,
    pub source: SocketAddrV6,
    pub destination: Ipv6Addr,
    pub index: u32,
}

pub(super) fn configure(socket: &socket2::Socket) {
    let enabled: libc::c_int = 1;
    // SAFETY: setsockopt reads a live integer of the declared size synchronously.
    let result = unsafe {
        libc::setsockopt(
            socket.as_raw_fd(),
            libc::IPPROTO_IPV6,
            libc::IPV6_RECVPKTINFO,
            (&enabled as *const libc::c_int).cast(),
            size_of::<libc::c_int>() as _,
        )
    };
    assert_eq!(
        result,
        0,
        "packet-info oracle setup: {}",
        io::Error::last_os_error()
    );
}

pub(super) async fn receive(socket: &UdpSocket) -> io::Result<Frame> {
    socket
        .async_io(Interest::READABLE, || {
            let mut bytes = [0u8; 2048];
            let mut control = [0usize; 32];
            // SAFETY: each receive has initialized aligned peer/control storage and
            // one live writable payload; pointers are used only during recvmsg.
            unsafe {
                let mut peer: libc::sockaddr_in6 = zeroed();
                let mut iov = libc::iovec {
                    iov_base: bytes.as_mut_ptr().cast(),
                    iov_len: bytes.len(),
                };
                let mut message: libc::msghdr = zeroed();
                message.msg_name = (&mut peer as *mut libc::sockaddr_in6).cast();
                message.msg_namelen = size_of::<libc::sockaddr_in6>() as _;
                message.msg_iov = &mut iov;
                message.msg_iovlen = 1;
                message.msg_control = control.as_mut_ptr().cast();
                message.msg_controllen = size_of_val(&control) as _;
                let count = libc::recvmsg(socket.as_raw_fd(), &mut message, 0);
                if count < 0 {
                    return Err(io::Error::last_os_error());
                }
                assert_eq!(message.msg_flags & (libc::MSG_TRUNC | libc::MSG_CTRUNC), 0);
                assert_eq!(peer.sin6_family as i32, libc::AF_INET6);
                let mut header = libc::CMSG_FIRSTHDR(&message);
                let mut info = None;
                while !header.is_null() {
                    if (*header).cmsg_level == libc::IPPROTO_IPV6
                        && (*header).cmsg_type == libc::IPV6_PKTINFO
                    {
                        assert!(
                            (*header).cmsg_len as usize
                                >= libc::CMSG_LEN(size_of::<libc::in6_pktinfo>() as _) as usize
                        );
                        assert!(info.is_none(), "duplicate packet-info in wire oracle");
                        let packet =
                            std::ptr::read(libc::CMSG_DATA(header).cast::<libc::in6_pktinfo>());
                        info = Some((
                            Ipv6Addr::from(packet.ipi6_addr.s6_addr),
                            packet.ipi6_ifindex,
                        ));
                    }
                    header = libc::CMSG_NXTHDR(&message, header);
                }
                let (destination, index) =
                    info.expect("wire oracle requires actual destination and arrival index");
                Ok(Frame {
                    bytes: bytes[..count as usize].to_vec(),
                    source: SocketAddrV6::new(
                        Ipv6Addr::from(peer.sin6_addr.s6_addr),
                        u16::from_be(peer.sin6_port),
                        0,
                        peer.sin6_scope_id,
                    ),
                    destination,
                    index,
                })
            }
        })
        .await
}
