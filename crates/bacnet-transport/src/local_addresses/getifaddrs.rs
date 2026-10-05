//! The host's IPv4 addresses from `getifaddrs`, copied out while the OS list
//! is alive.
#![allow(unsafe_code)]

use std::io;
use std::net::Ipv4Addr;

use super::ReportedAddress;

/// Every IPv4 address `getifaddrs` reports, on any interface.
pub(super) fn reported_ipv4() -> io::Result<Vec<ReportedAddress>> {
    struct IfAddrsGuard(*mut libc::ifaddrs);

    impl Drop for IfAddrsGuard {
        fn drop(&mut self) {
            // SAFETY: the pointer was returned by `getifaddrs` and this guard
            // owns the corresponding single `freeifaddrs` call.
            unsafe { libc::freeifaddrs(self.0) }
        }
    }

    let mut head = std::ptr::null_mut();
    // SAFETY: `getifaddrs` initializes `head` on success. The guarded list is
    // walked only through non-null nodes and address-family-checked pointers.
    if unsafe { libc::getifaddrs(&mut head) } != 0 {
        return Err(io::Error::last_os_error());
    }
    let _guard = IfAddrsGuard(head);
    let mut reported = Vec::new();
    let mut current = head;
    while !current.is_null() {
        // SAFETY: `current` is a node in the live guarded list.
        let entry = unsafe { &*current };
        if !entry.ifa_addr.is_null() {
            // SAFETY: the non-null sockaddr is valid for its reported family.
            let family = unsafe { (*entry.ifa_addr).sa_family as i32 };
            if family == libc::AF_INET {
                // SAFETY: family AF_INET selects the sockaddr_in layout.
                let address = unsafe { &*(entry.ifa_addr as *const libc::sockaddr_in) };
                reported.push(ReportedAddress {
                    ip: Ipv4Addr::from(address.sin_addr.s_addr.to_ne_bytes()),
                    // getifaddrs lists the addresses assigned to interfaces
                    // and reports no duplicate address detection state.
                    assigned: true,
                });
            }
        }
        current = entry.ifa_next;
    }
    Ok(reported)
}
