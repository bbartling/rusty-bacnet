//! Copy local addresses while the OS getifaddrs allocation is alive.
#![allow(unsafe_code)]

use std::{io, net::Ipv6Addr};

use super::{Candidate, SelectedLink};

pub(super) fn enumerate() -> io::Result<Vec<Candidate>> {
    struct Addresses(*mut libc::ifaddrs);
    impl Drop for Addresses {
        fn drop(&mut self) {
            // SAFETY: this guard uniquely owns a successful getifaddrs list.
            unsafe { libc::freeifaddrs(self.0) };
        }
    }
    let mut head = std::ptr::null_mut();
    // SAFETY: the OS initializes the writable pointer; the guard frees success.
    if unsafe { libc::getifaddrs(&mut head) } != 0 {
        return Err(io::Error::last_os_error());
    }
    let _addresses = Addresses(head);
    let mut candidates = Vec::new();
    let mut current = head;
    while !current.is_null() {
        // SAFETY: current is an OS node in the still-live guarded allocation.
        let entry = unsafe { &*current };
        if !entry.ifa_addr.is_null() && !entry.ifa_name.is_null() {
            // SAFETY: a non-null OS sockaddr is valid for its declared family.
            if unsafe { (*entry.ifa_addr).sa_family as i32 } == libc::AF_INET6 {
                // SAFETY: AF_INET6 selects this layout; the OS name is NUL-terminated.
                let (address, index) = unsafe {
                    (
                        &*(entry.ifa_addr as *const libc::sockaddr_in6),
                        libc::if_nametoindex(entry.ifa_name),
                    )
                };
                candidates.push(Candidate {
                    link: SelectedLink {
                        address: Ipv6Addr::from(address.sin6_addr.s6_addr),
                        index,
                    },
                    up: entry.ifa_flags & libc::IFF_UP as u32 != 0,
                    multicast: entry.ifa_flags & libc::IFF_MULTICAST as u32 != 0,
                    loopback: entry.ifa_flags & libc::IFF_LOOPBACK as u32 != 0,
                });
            }
        }
        current = entry.ifa_next;
    }
    Ok(candidates)
}
