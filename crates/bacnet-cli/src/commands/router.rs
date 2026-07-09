//! Router and BBMD commands.

use std::net::Ipv4Addr;
use std::time::Duration;

use bacnet_client::client::BACnetClient;
use bacnet_transport::bip::BipTransport;
use bacnet_transport::port::TransportPort;

use crate::output::{self, device_info, DeviceInfo, OutputFormat};

/// Display all cached discovered devices from the client's device table.
pub async fn devices_cmd<T: TransportPort + 'static>(
    client: &BACnetClient<T>,
    format: OutputFormat,
) -> Result<(), Box<dyn std::error::Error>> {
    let devices = client.discovered_devices().await;
    let infos: Vec<DeviceInfo> = devices.iter().map(device_info).collect();
    output::print_devices(&infos, format);
    Ok(())
}

/// Send Who-Is-Router-To-Network.
pub async fn whois_router_cmd<T: TransportPort + 'static>(
    client: &BACnetClient<T>,
    format: OutputFormat,
) -> Result<(), Box<dyn std::error::Error>> {
    client.clear_routers().await;
    client.who_is_router_to_network(None).await?;
    tokio::time::sleep(Duration::from_secs(3)).await;
    let routers = client.discovered_routers().await;

    match format {
        OutputFormat::Table => {
            if routers.is_empty() {
                println!("No routers discovered.");
            } else {
                let mut table = comfy_table::Table::new();
                table.set_header(vec!["Router", "Networks"]);
                for r in &routers {
                    let addr = bip_mac_display(r.router_mac.as_slice());
                    table.add_row(vec![
                        addr,
                        r.networks
                            .iter()
                            .map(|n| n.to_string())
                            .collect::<Vec<_>>()
                            .join(", "),
                    ]);
                }
                println!("{table}");
            }
        }
        OutputFormat::Json => {
            let json_routers: Vec<_> = routers
                .iter()
                .map(|r| {
                    serde_json::json!({
                        "source": bip_mac_display(r.router_mac.as_slice()),
                        "networks": r.networks,
                    })
                })
                .collect();
            println!(
                "{}",
                serde_json::to_string_pretty(&json_routers).unwrap_or_default()
            );
        }
    }
    Ok(())
}

fn bip_mac_display(mac: &[u8]) -> String {
    if mac.len() == 6 {
        format!(
            "{}.{}.{}.{}:{:04x}",
            mac[0], mac[1], mac[2], mac[3], u16::from_be_bytes([mac[4], mac[5]])
        )
    } else {
        mac.iter().map(|b| format!("{b:02x}")).collect::<String>()
    }
}

/// Read the Broadcast Distribution Table from a BBMD.
pub async fn bdt_cmd(
    client: &BACnetClient<BipTransport>,
    mac: &[u8],
    format: OutputFormat,
) -> Result<(), Box<dyn std::error::Error>> {
    let entries = client.read_bdt(mac).await?;
    match format {
        OutputFormat::Table => {
            if entries.is_empty() {
                println!("BDT is empty.");
            } else {
                let mut table = comfy_table::Table::new();
                table.set_header(vec!["IP", "Port", "Broadcast Mask"]);
                for e in &entries {
                    table.add_row(vec![
                        format!("{}", Ipv4Addr::from(e.ip)),
                        format!("{}", e.port),
                        format!("{}", Ipv4Addr::from(e.broadcast_mask)),
                    ]);
                }
                println!("{table}");
            }
        }
        OutputFormat::Json => {
            let json_entries: Vec<_> = entries
                .iter()
                .map(|e| {
                    serde_json::json!({
                        "ip": format!("{}", Ipv4Addr::from(e.ip)),
                        "port": e.port,
                        "broadcast_mask": format!("{}", Ipv4Addr::from(e.broadcast_mask)),
                    })
                })
                .collect();
            println!(
                "{}",
                serde_json::to_string_pretty(&json_entries).unwrap_or_default()
            );
        }
    }
    Ok(())
}

/// Read the Foreign Device Table from a BBMD.
pub async fn fdt_cmd(
    client: &BACnetClient<BipTransport>,
    mac: &[u8],
    format: OutputFormat,
) -> Result<(), Box<dyn std::error::Error>> {
    let entries = client.read_fdt(mac).await?;
    match format {
        OutputFormat::Table => {
            if entries.is_empty() {
                println!("FDT is empty.");
            } else {
                let mut table = comfy_table::Table::new();
                table.set_header(vec!["IP", "Port", "TTL", "Remaining"]);
                for e in &entries {
                    table.add_row(vec![
                        format!("{}", Ipv4Addr::from(e.ip)),
                        format!("{}", e.port),
                        format!("{}s", e.ttl),
                        format!("{}s", e.seconds_remaining),
                    ]);
                }
                println!("{table}");
            }
        }
        OutputFormat::Json => {
            let json_entries: Vec<_> = entries
                .iter()
                .map(|e| {
                    serde_json::json!({
                        "ip": format!("{}", Ipv4Addr::from(e.ip)),
                        "port": e.port,
                        "ttl": e.ttl,
                        "seconds_remaining": e.seconds_remaining,
                    })
                })
                .collect();
            println!(
                "{}",
                serde_json::to_string_pretty(&json_entries).unwrap_or_default()
            );
        }
    }
    Ok(())
}

/// Register as a foreign device with a BBMD.
pub async fn register_cmd(
    client: &BACnetClient<BipTransport>,
    mac: &[u8],
    ttl: u16,
    format: OutputFormat,
) -> Result<(), Box<dyn std::error::Error>> {
    let result = client.register_foreign_device_bvlc(mac, ttl).await?;
    output::print_success(
        &format!("Register-Foreign-Device result: {result:?}"),
        format,
    );
    Ok(())
}

/// Unregister from a BBMD (delete our own FDT entry).
pub async fn unregister_cmd(
    client: &BACnetClient<BipTransport>,
    mac: &[u8],
    format: OutputFormat,
) -> Result<(), Box<dyn std::error::Error>> {
    // To unregister, we delete our own entry from the BBMD's FDT.
    // Our local MAC contains our IP and port.
    let local_mac = client.local_mac();
    if local_mac.len() != 6 {
        return Err("Cannot determine local BIP address".into());
    }
    let ip = [local_mac[0], local_mac[1], local_mac[2], local_mac[3]];
    let port = u16::from_be_bytes([local_mac[4], local_mac[5]]);
    let result = client.delete_fdt_entry(mac, ip, port).await?;
    output::print_success(
        &format!("Delete-Foreign-Device-Table-Entry result: {result:?}"),
        format,
    );
    Ok(())
}
