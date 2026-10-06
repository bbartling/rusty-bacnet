//! The host's IPv4 addresses from `getifaddrs`, copied out while the OS list
//! is alive.
#![allow(unsafe_code)]

use std::io;
use std::net::Ipv4Addr;

use super::ReportedAddress;

/// One IPv4 address `getifaddrs` reports, with its interface's netmask and
/// flags.
struct Entry {
    ip: Ipv4Addr,
    #[cfg_attr(not(test), allow(dead_code))]
    netmask: Option<Ipv4Addr>,
    #[cfg_attr(not(test), allow(dead_code))]
    flags: libc::c_uint,
}

/// The IPv4 address in `address`, if it is a non-null IPv4 socket address.
///
/// # Safety
///
/// `address` is null or points to a socket address that is valid for its
/// reported family.
unsafe fn ipv4_of(address: *const libc::sockaddr) -> Option<Ipv4Addr> {
    if address.is_null() {
        return None;
    }
    // SAFETY: the non-null sockaddr is valid for its reported family.
    if unsafe { (*address).sa_family as i32 } != libc::AF_INET {
        return None;
    }
    // SAFETY: family AF_INET selects the sockaddr_in layout.
    let address = unsafe { &*(address as *const libc::sockaddr_in) };
    Some(Ipv4Addr::from(address.sin_addr.s_addr.to_ne_bytes()))
}

/// Every IPv4 address `getifaddrs` reports, on any interface.
fn entries() -> io::Result<Vec<Entry>> {
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
    let mut entries = Vec::new();
    let mut current = head;
    while !current.is_null() {
        // SAFETY: `current` is a node in the live guarded list.
        let entry = unsafe { &*current };
        // SAFETY: the node's socket addresses are null or valid for their
        // reported families while the list is alive.
        if let Some(ip) = unsafe { ipv4_of(entry.ifa_addr) } {
            entries.push(Entry {
                ip,
                // SAFETY: as above.
                netmask: unsafe { ipv4_of(entry.ifa_netmask) },
                flags: entry.ifa_flags,
            });
        }
        current = entry.ifa_next;
    }
    Ok(entries)
}

/// Every IPv4 address `getifaddrs` reports, on any interface.
pub(super) fn reported_ipv4() -> io::Result<Vec<ReportedAddress>> {
    Ok(entries()?
        .into_iter()
        .map(|entry| ReportedAddress {
            ip: entry.ip,
            // getifaddrs lists the addresses assigned to interfaces and
            // reports no duplicate address detection state.
            assigned: true,
        })
        .collect())
}

/// The netmask of the broadcast-capable interface that has `ip`.
#[cfg(test)]
pub(super) fn broadcast_netmask(ip: Ipv4Addr) -> Option<Ipv4Addr> {
    entries()
        .ok()?
        .into_iter()
        .find(|entry| entry.ip == ip && entry.flags & libc::IFF_BROADCAST as libc::c_uint != 0)?
        .netmask
}
