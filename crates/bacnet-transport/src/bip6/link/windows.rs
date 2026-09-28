//! Windows adapter discovery. No OS pointer escapes the owned result buffer.
#![allow(unsafe_code)]

use std::{
    io,
    mem::{size_of, MaybeUninit},
    net::Ipv6Addr,
};
use windows_sys::Win32::{
    Foundation::{ERROR_BUFFER_OVERFLOW, ERROR_NO_DATA, NO_ERROR},
    NetworkManagement::{IpHelper::*, Ndis::IfOperStatusUp},
    Networking::WinSock::{IpDadStatePreferred, AF_INET6, SOCKADDR_IN6},
};

use super::{Candidate, SelectedLink};

pub(super) fn enumerate() -> io::Result<Vec<Candidate>> {
    let mut bytes = 15_000u32;
    for _ in 0..3 {
        if bytes > 8 * 1024 * 1024 {
            return Err(io::Error::other(
                "IPv6 adapter inventory exceeded bounded allocation",
            ));
        }
        let count = (bytes as usize).div_ceil(size_of::<IP_ADAPTER_ADDRESSES_LH>());
        let mut buffer = vec![MaybeUninit::<IP_ADAPTER_ADDRESSES_LH>::uninit(); count];
        let head = buffer.as_mut_ptr().cast::<IP_ADAPTER_ADDRESSES_LH>();
        // SAFETY: buffer has the required size/alignment. The synchronous OS
        // call writes adapter records and pointers into this live allocation.
        let status = unsafe {
            GetAdaptersAddresses(
                AF_INET6 as u32,
                GAA_FLAG_SKIP_ANYCAST | GAA_FLAG_SKIP_MULTICAST | GAA_FLAG_SKIP_DNS_SERVER,
                std::ptr::null(),
                head,
                &mut bytes,
            )
        };
        if status == ERROR_BUFFER_OVERFLOW {
            continue;
        }
        if status == ERROR_NO_DATA {
            return Ok(Vec::new());
        }
        if status != NO_ERROR {
            return Err(io::Error::from_raw_os_error(status as i32));
        }
        let mut candidates = Vec::new();
        let mut current = head;
        while !current.is_null() {
            // SAFETY: success populated the OS list within buffer, which remains
            // allocated and unmodified until every address has been copied out.
            let adapter = unsafe { &*current };
            let mut unicast = adapter.FirstUnicastAddress;
            while !unicast.is_null() {
                // SAFETY: this is an OS-populated node in the same live list.
                let item = unsafe { &*unicast };
                if item.DadState == IpDadStatePreferred
                    && !item.Address.lpSockaddr.is_null()
                    && item.Address.iSockaddrLength as usize >= size_of::<SOCKADDR_IN6>()
                {
                    // SAFETY: length and family are checked before reading the IPv6 layout.
                    if unsafe { (*item.Address.lpSockaddr).sa_family } == AF_INET6 {
                        let address = unsafe { &*item.Address.lpSockaddr.cast::<SOCKADDR_IN6>() };
                        candidates.push(Candidate {
                            link: SelectedLink {
                                address: Ipv6Addr::from(unsafe { address.sin6_addr.u.Byte }),
                                index: adapter.Ipv6IfIndex,
                            },
                            up: adapter.OperStatus == IfOperStatusUp,
                            multicast: unsafe { adapter.Anonymous2.Flags }
                                & IP_ADAPTER_NO_MULTICAST
                                == 0,
                            loopback: adapter.IfType == IF_TYPE_SOFTWARE_LOOPBACK,
                        });
                    }
                }
                unicast = item.Next;
            }
            current = adapter.Next;
        }
        return Ok(candidates);
    }
    Err(io::Error::other(
        "IPv6 adapter inventory kept changing during discovery",
    ))
}
