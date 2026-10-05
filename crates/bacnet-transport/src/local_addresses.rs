//! Local interface address discovery for wildcard-bound UDP ingress checks.
//!
//! The OS call (`getifaddrs` on Unix and Apple targets, `GetAdaptersAddresses`
//! on Windows) only reports addresses; [`host_ipv4`] decides which of them are
//! the host's, the same way on every OS, so its rules are unit-tested
//! everywhere. Both calls can block, so async callers run them on a blocking
//! thread.

use std::io;
use std::net::{Ipv4Addr, SocketAddr, UdpSocket};

#[cfg(any(
    target_os = "linux",
    target_os = "l4re",
    target_os = "android",
    target_os = "emscripten",
    target_vendor = "apple",
    target_os = "freebsd",
    target_os = "dragonfly",
    target_os = "openbsd",
    target_os = "netbsd",
    target_os = "solaris",
    target_os = "illumos",
    target_os = "haiku",
    target_os = "nto",
    target_os = "hurd",
    target_os = "fuchsia",
))]
mod getifaddrs;
#[cfg(any(
    target_os = "linux",
    target_os = "l4re",
    target_os = "android",
    target_os = "emscripten",
    target_vendor = "apple",
    target_os = "freebsd",
    target_os = "dragonfly",
    target_os = "openbsd",
    target_os = "netbsd",
    target_os = "solaris",
    target_os = "illumos",
    target_os = "haiku",
    target_os = "nto",
    target_os = "hurd",
    target_os = "fuchsia",
))]
use getifaddrs::reported_ipv4;

/// An IPv4 address the OS reports on one of the host's interfaces.
#[derive(Clone, Copy, Debug)]
struct ReportedAddress {
    ip: Ipv4Addr,
    /// The address is configured on this host. `getifaddrs` reports only
    /// such addresses. Windows also reports addresses that duplicate address
    /// detection found in use by another host, and invalid ones, which are
    /// not (see `assigned_on_windows`).
    assigned: bool,
}

/// The host's unicast IPv4 addresses: every assigned address the OS reports,
/// sorted and without duplicates. The list answers "is this one of the host's
/// addresses", not "can a socket bind it right now".
///
/// Loopback and link-local addresses stay, and so do addresses of interfaces
/// that are down: no datagram arrives through those, and a BDT row naming one
/// still names this host. Unspecified, broadcast and multicast addresses never
/// identify this host and are dropped.
fn host_ipv4(reported: impl IntoIterator<Item = ReportedAddress>) -> Vec<Ipv4Addr> {
    let mut ips: Vec<Ipv4Addr> = reported
        .into_iter()
        .filter(|address| address.assigned)
        .map(|address| address.ip)
        .filter(|ip| !ip.is_unspecified() && !ip.is_broadcast() && !ip.is_multicast())
        .collect();
    ips.sort_unstable();
    ips.dedup();
    ips
}

/// Whether Windows counts an address in this duplicate address detection
/// state as the host's. A tentative address is still being checked, and
/// Windows also reports a static address on a disconnected adapter that way,
/// so it counts, like preferred and deprecated ones. A duplicate address is in
/// use by another host, and an invalid one is not configured.
#[cfg(windows)]
fn assigned_on_windows(dad_state: windows_sys::Win32::Networking::WinSock::NL_DAD_STATE) -> bool {
    use windows_sys::Win32::Networking::WinSock::{IpDadStateDuplicate, IpDadStateInvalid};
    dad_state != IpDadStateDuplicate && dad_state != IpDadStateInvalid
}

/// Every unicast IPv4 address `GetAdaptersAddresses` reports, on any adapter.
#[cfg(windows)]
fn reported_ipv4() -> io::Result<Vec<ReportedAddress>> {
    use std::net::IpAddr;
    use windows_sys::Win32::Networking::WinSock::AF_INET;

    Ok(crate::windows_adapters::unicast_addresses(AF_INET)?
        .into_iter()
        .filter_map(|address| match address.ip {
            IpAddr::V4(ip) => Some(ReportedAddress {
                ip,
                assigned: assigned_on_windows(address.dad_state),
            }),
            IpAddr::V6(_) => None,
        })
        .collect())
}

#[cfg(not(any(
    target_os = "linux",
    target_os = "l4re",
    target_os = "android",
    target_os = "emscripten",
    target_vendor = "apple",
    target_os = "freebsd",
    target_os = "dragonfly",
    target_os = "openbsd",
    target_os = "netbsd",
    target_os = "solaris",
    target_os = "illumos",
    target_os = "haiku",
    target_os = "nto",
    target_os = "hurd",
    target_os = "fuchsia",
    windows,
)))]
fn reported_ipv4() -> io::Result<Vec<ReportedAddress>> {
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        "listing local IPv4 addresses is not supported on this OS",
    ))
}

/// The host's local unicast IPv4 addresses (see [`host_ipv4`]).
pub(crate) fn ipv4() -> io::Result<Vec<Ipv4Addr>> {
    reported_ipv4().map(host_ipv4)
}

/// The host's local IPv4 address toward the default route: the local address
/// of a UDP socket connected to a public address. Connecting a UDP socket
/// sends nothing. `None` without a default route.
pub(crate) fn route_ipv4() -> Option<Ipv4Addr> {
    let socket = UdpSocket::bind((Ipv4Addr::UNSPECIFIED, 0)).ok()?;
    socket.connect((Ipv4Addr::new(8, 8, 8, 8), 80)).ok()?;
    match socket.local_addr().ok()? {
        SocketAddr::V4(v4) => Some(*v4.ip()),
        SocketAddr::V6(_) => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn assigned(ip: Ipv4Addr) -> ReportedAddress {
        ReportedAddress { ip, assigned: true }
    }

    #[test]
    fn host_list_is_sorted_and_deduplicated() {
        let lan = Ipv4Addr::new(192, 0, 2, 10);
        let other = Ipv4Addr::new(198, 51, 100, 7);
        // The same address on two adapters, or twice on one, is listed once.
        let reported = [lan, Ipv4Addr::LOCALHOST, other, lan].map(assigned);
        assert_eq!(host_ipv4(reported), [Ipv4Addr::LOCALHOST, lan, other]);
        assert!(host_ipv4([]).is_empty());
    }

    #[test]
    fn host_list_keeps_loopback_and_link_local_addresses() {
        let loopback_alias = Ipv4Addr::new(127, 0, 0, 2);
        let link_local = Ipv4Addr::new(169, 254, 10, 20);
        let reported = [link_local, loopback_alias, Ipv4Addr::LOCALHOST].map(assigned);
        assert_eq!(
            host_ipv4(reported),
            [Ipv4Addr::LOCALHOST, loopback_alias, link_local]
        );
    }

    #[test]
    fn host_list_drops_unassigned_and_non_unicast_addresses() {
        let lan = Ipv4Addr::new(192, 0, 2, 10);
        let duplicate = ReportedAddress {
            ip: Ipv4Addr::new(192, 0, 2, 11),
            assigned: false,
        };
        let reported = [
            duplicate,
            assigned(Ipv4Addr::UNSPECIFIED),
            assigned(Ipv4Addr::BROADCAST),
            assigned(Ipv4Addr::new(224, 0, 0, 1)),
            assigned(Ipv4Addr::new(239, 255, 255, 250)),
            assigned(lan),
        ];
        assert_eq!(host_ipv4(reported), [lan]);
        // An address assigned on one adapter and not on another is listed.
        let twice = [
            ReportedAddress {
                ip: lan,
                assigned: false,
            },
            assigned(lan),
        ];
        assert_eq!(host_ipv4(twice), [lan]);
    }

    #[cfg(windows)]
    #[test]
    fn windows_counts_every_dad_state_but_duplicate_and_invalid_as_assigned() {
        use windows_sys::Win32::Networking::WinSock::{
            IpDadStateDeprecated, IpDadStateDuplicate, IpDadStateInvalid, IpDadStatePreferred,
            IpDadStateTentative,
        };
        for state in [
            IpDadStatePreferred,
            IpDadStateDeprecated,
            IpDadStateTentative,
        ] {
            assert!(assigned_on_windows(state), "{state}");
        }
        for state in [IpDadStateDuplicate, IpDadStateInvalid] {
            assert!(!assigned_on_windows(state), "{state}");
        }
    }

    #[test]
    fn the_host_list_includes_loopback_and_the_default_route_address() {
        let ips = match ipv4() {
            Ok(ips) => ips,
            // Only an OS without a listing call may fail.
            Err(e) => {
                assert!(
                    cfg!(not(any(unix, windows))) && e.kind() == io::ErrorKind::Unsupported,
                    "{e}"
                );
                return;
            }
        };
        assert!(ips.contains(&Ipv4Addr::LOCALHOST), "{ips:?}");
        // A real adapter's address, so a decode or filter regression fails
        // here and not only on loopback. A host without a default route skips
        // this half.
        if let Some(route) = route_ipv4() {
            assert!(
                ips.contains(&route),
                "default-route address {route} is not in {ips:?}"
            );
        }
    }
}
