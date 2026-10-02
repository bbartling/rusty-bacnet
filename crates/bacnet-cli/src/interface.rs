//! Interactive stderr prompt for the shell's BACnet/IP interface.

use std::io::{self, Write as _};
use std::net::Ipv4Addr;

use owo_colors::OwoColorize;

use crate::core::interfaces::list_ipv4_interfaces;

/// Prompt the user to select a network interface. Returns (ip, broadcast).
pub(crate) fn pick_interface() -> Result<(Ipv4Addr, Ipv4Addr), Box<dyn std::error::Error>> {
    let ifaces = list_ipv4_interfaces();
    if ifaces.is_empty() {
        eprintln!("No network interfaces found, binding to 0.0.0.0");
        return Ok((Ipv4Addr::UNSPECIFIED, Ipv4Addr::BROADCAST));
    }
    if ifaces.len() == 1 {
        let iface = &ifaces[0];
        eprintln!(
            "Using interface {} ({}, broadcast {})",
            iface.name.bold(),
            iface.ip,
            iface.broadcast
        );
        return Ok((iface.ip, iface.broadcast));
    }

    eprintln!("{}", "Select a network interface:".bold());
    for (i, iface) in ifaces.iter().enumerate() {
        eprintln!(
            "  {}) {} — {} (broadcast {})",
            (i + 1).bold(),
            iface.name.bold(),
            iface.ip,
            iface.broadcast.dimmed()
        );
    }
    eprint!("Enter selection [1-{}]: ", ifaces.len());
    io::stderr().flush()?;

    let mut input = String::new();
    io::stdin().read_line(&mut input)?;
    let choice: usize = input
        .trim()
        .parse()
        .map_err(|_| format!("invalid selection: '{}'", input.trim()))?;
    if choice < 1 || choice > ifaces.len() {
        return Err(format!("selection out of range: {choice}").into());
    }
    let iface = &ifaces[choice - 1];
    eprintln!("Using interface {} ({})", iface.name.bold(), iface.ip);
    Ok((iface.ip, iface.broadcast))
}
