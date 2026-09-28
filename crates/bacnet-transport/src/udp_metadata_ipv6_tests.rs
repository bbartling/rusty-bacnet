use super::*;
use std::mem::{size_of, zeroed};

fn decode_control(index: u32, short: bool, duplicate: bool) -> io::Result<(IpAddr, Option<u32>)> {
    let mut control = [0usize; 32];
    // SAFETY: message points into aligned, initialized test storage; all cmsg
    // lengths except the deliberate short payload remain within that storage.
    unsafe {
        let space = libc::CMSG_SPACE(size_of::<libc::in6_pktinfo>() as _) as usize;
        let copies = if duplicate { 2 } else { 1 };
        assert!(space * copies <= size_of_val(&control));
        for number in 0..copies {
            let header = control
                .as_mut_ptr()
                .cast::<u8>()
                .add(number * space)
                .cast::<libc::cmsghdr>();
            (*header).cmsg_level = libc::IPPROTO_IPV6;
            (*header).cmsg_type = libc::IPV6_PKTINFO;
            (*header).cmsg_len =
                libc::CMSG_LEN((size_of::<libc::in6_pktinfo>() - usize::from(short)) as _) as _;
            std::ptr::write(
                libc::CMSG_DATA(header).cast::<libc::in6_pktinfo>(),
                libc::in6_pktinfo {
                    ipi6_addr: libc::in6_addr {
                        s6_addr: "fd12::1".parse::<Ipv6Addr>().unwrap().octets(),
                    },
                    ipi6_ifindex: index,
                },
            );
        }
        let mut message: libc::msghdr = zeroed();
        message.msg_control = control.as_mut_ptr().cast();
        message.msg_controllen = (space * copies) as _;
        unix_destination(&message, IpVersion::V6)
    }
}

#[test]
fn packet_info_keeps_destination_and_arrival_index_together() {
    assert_eq!(
        decode_control(7, false, false).unwrap(),
        ("fd12::1".parse().unwrap(), Some(7))
    );
    // Zero is retained as untrusted metadata; selected-link admission rejects it.
    assert_eq!(decode_control(0, false, false).unwrap().1, Some(0));
}

#[test]
fn short_duplicate_or_missing_ipv6_packet_info_is_invalid() {
    assert_eq!(
        decode_control(7, true, false).unwrap_err().kind(),
        io::ErrorKind::InvalidData
    );
    assert_eq!(
        decode_control(7, false, true).unwrap_err().kind(),
        io::ErrorKind::InvalidData
    );
    // SAFETY: the all-zero message has no control buffer, as intended here.
    let missing = unsafe { unix_destination(&zeroed(), IpVersion::V6) }.unwrap_err();
    assert_eq!(missing.kind(), io::ErrorKind::InvalidData);
}
