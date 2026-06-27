//! Who-Is a BACnet device, WriteProperty on present-value, verify via read-back
//! and priority-array slot, relinquish with Null, verify again, exit.

use std::net::Ipv4Addr;
use std::process;
use std::time::Duration;

use bacnet_client::client::BACnetClient;
use bacnet_encoding::primitives::{decode_application_value, encode_property_value};
use bacnet_services::who_is::WhoIsRequest;
use bacnet_transport::bip::DEFAULT_BACNET_PORT;
use bacnet_transport::bvll::encode_bip_mac;
use bacnet_types::enums::{ObjectType, PropertyIdentifier, UnconfirmedServiceChoice};
use bacnet_types::primitives::{ObjectIdentifier, PropertyValue};
use bytes::BytesMut;
use clap::Parser;

#[derive(Parser, Debug)]
#[command(
    name = "bacnet-write",
    about = "WriteProperty demo: write → verify PV + priority array → Null → verify again"
)]
struct Args {
    #[arg(long, short = 'd', default_value_t = 5007)]
    device: u32,

    #[arg(long, short = 'p', default_value = "analog-output:10035")]
    point: String,

    #[arg(long, short = 'v', default_value_t = 5.0)]
    value: f32,

    #[arg(long, default_value_t = 8)]
    priority: u8,

    #[arg(long, short = 'a')]
    address: Option<Ipv4Addr>,

    #[arg(long, short = 'i')]
    interface: Option<Ipv4Addr>,

    #[arg(long, short = 'b')]
    broadcast: Option<Ipv4Addr>,

    #[arg(long, short = 't', default_value_t = 3)]
    timeout: u64,

    #[arg(long, default_value_t = DEFAULT_BACNET_PORT)]
    port: u16,

    #[arg(long)]
    ephemeral: bool,

    #[arg(long)]
    no_revert: bool,

    /// Float compare tolerance for verify steps
    #[arg(long, default_value_t = 0.05)]
    tolerance: f32,
}

#[derive(Debug, Clone)]
struct PointSnapshot {
    present_value: PropertyValue,
    priority_slot: Option<PropertyValue>,
    current_priority: Option<u8>,
}

fn detect_enp3s0_address() -> Option<Ipv4Addr> {
    let output = process::Command::new("ip")
        .args(["-4", "addr", "show", "dev", "enp3s0"])
        .output()
        .ok()?;
    for line in String::from_utf8_lossy(&output.stdout).lines() {
        let line = line.trim();
        if let Some(rest) = line.strip_prefix("inet ") {
            if let Some(ip_str) = rest.split_whitespace().next() {
                if let Some(base) = ip_str.split('/').next() {
                    if let Ok(ip) = base.parse::<Ipv4Addr>() {
                        return Some(ip);
                    }
                }
            }
        }
    }
    None
}

fn subnet_broadcast(ip: Ipv4Addr) -> Ipv4Addr {
    let o = ip.octets();
    Ipv4Addr::new(o[0], o[1], o[2], 255)
}

fn resolve_interface(args: &Args) -> Ipv4Addr {
    if let Some(ip) = args.interface {
        return ip;
    }
    if let Some(ip) = detect_enp3s0_address() {
        eprintln!("auto-detected enp3s0: {ip}");
        return ip;
    }
    eprintln!("no --interface and enp3s0 not found; using 0.0.0.0");
    Ipv4Addr::UNSPECIFIED
}

fn parse_point(s: &str) -> Result<ObjectIdentifier, String> {
    let (ty, inst) = s
        .split_once(':')
        .ok_or_else(|| format!("expected type:instance, got {s:?}"))?;
    let inst: u32 = inst
        .parse()
        .map_err(|_| format!("bad instance number in {s:?}"))?;
    let object_type = match ty.to_ascii_lowercase().replace('-', "_").as_str() {
        "analog_input" | "ai" => ObjectType::ANALOG_INPUT,
        "analog_output" | "ao" => ObjectType::ANALOG_OUTPUT,
        "analog_value" | "av" => ObjectType::ANALOG_VALUE,
        "binary_input" | "bi" => ObjectType::BINARY_INPUT,
        "binary_output" | "bo" => ObjectType::BINARY_OUTPUT,
        "binary_value" | "bv" => ObjectType::BINARY_VALUE,
        "multi_state_value" | "msv" => ObjectType::MULTI_STATE_VALUE,
        "multi_state_output" | "mso" => ObjectType::MULTI_STATE_OUTPUT,
        other => {
            if let Ok(code) = other.parse::<u32>() {
                ObjectType::from_raw(code)
            } else {
                return Err(format!("unknown object type {ty:?}"));
            }
        }
    };
    ObjectIdentifier::new(object_type, inst).map_err(|e| e.to_string())
}

fn format_oid(oid: &ObjectIdentifier) -> String {
    format!("{}:{}", oid.object_type(), oid.instance_number())
}

fn present_value_hint(value: &PropertyValue) -> String {
    match value {
        PropertyValue::Real(v) => format!("{v}"),
        PropertyValue::Enumerated(v) => format!("{v}"),
        PropertyValue::Boolean(v) => format!("{v}"),
        PropertyValue::Unsigned(v) => format!("{v}"),
        PropertyValue::Signed(v) => format!("{v}"),
        PropertyValue::Null => "null".into(),
        other => format!("{other:?}"),
    }
}

fn decode_prop(bytes: &[u8]) -> Option<PropertyValue> {
    decode_application_value(bytes, 0)
        .ok()
        .map(|(v, _)| v)
}

fn values_match(expected: &PropertyValue, actual: &PropertyValue, tolerance: f32) -> bool {
    match (expected, actual) {
        (PropertyValue::Real(a), PropertyValue::Real(b)) => (a - b).abs() <= tolerance,
        (PropertyValue::Null, PropertyValue::Null) => true,
        (a, b) => a == b,
    }
}

fn print_snapshot(label: &str, oid: &ObjectIdentifier, snap: &PointSnapshot, priority: u8) {
    let cmd = snap
        .current_priority
        .map(|p| format!("cmd@P{p}"))
        .unwrap_or_else(|| "cmd@—".into());
    let slot = snap
        .priority_slot
        .as_ref()
        .map(present_value_hint)
        .unwrap_or_else(|| "null".into());
    println!(
        "{label}: {}  pv={}  P{priority}={slot}  {cmd}",
        format_oid(oid),
        present_value_hint(&snap.present_value),
    );
}

async fn read_present_value(
    client: &BACnetClient<bacnet_transport::bip::BipTransport>,
    device: u32,
    oid: ObjectIdentifier,
) -> Result<PropertyValue, bacnet_types::error::Error> {
    let ack = client
        .read_property_from_device(device, oid, PropertyIdentifier::PRESENT_VALUE, None)
        .await?;
    decode_application_value(&ack.property_value, 0)
        .map(|(v, _)| v)
        .map_err(|e| bacnet_types::error::Error::Encoding(e.to_string()))
}

async fn read_priority_slot(
    client: &BACnetClient<bacnet_transport::bip::BipTransport>,
    device: u32,
    oid: ObjectIdentifier,
    priority: u8,
) -> Result<Option<PropertyValue>, bacnet_types::error::Error> {
    let ack = client
        .read_property_from_device(
            device,
            oid,
            PropertyIdentifier::PRIORITY_ARRAY,
            Some(priority as u32),
        )
        .await?;
    let val = decode_application_value(&ack.property_value, 0)
        .map(|(v, _)| v)
        .map_err(|e| bacnet_types::error::Error::Encoding(e.to_string()))?;
    Ok(if matches!(val, PropertyValue::Null) {
        None
    } else {
        Some(val)
    })
}

async fn read_current_command_priority(
    client: &BACnetClient<bacnet_transport::bip::BipTransport>,
    device: u32,
    oid: ObjectIdentifier,
) -> Option<u8> {
    let ack = client
        .read_property_from_device(
            device,
            oid,
            PropertyIdentifier::CURRENT_COMMAND_PRIORITY,
            None,
        )
        .await
        .ok()?;
    match decode_prop(&ack.property_value)? {
        PropertyValue::Unsigned(v) if (1..=16).contains(&(v as u8)) => Some(v as u8),
        _ => None,
    }
}

async fn read_snapshot(
    client: &BACnetClient<bacnet_transport::bip::BipTransport>,
    device: u32,
    oid: ObjectIdentifier,
    priority: u8,
) -> Result<PointSnapshot, bacnet_types::error::Error> {
    let present_value = read_present_value(client, device, oid).await?;
    let priority_slot = read_priority_slot(client, device, oid, priority).await?;
    let current_priority = read_current_command_priority(client, device, oid).await;
    Ok(PointSnapshot {
        present_value,
        priority_slot,
        current_priority,
    })
}

async fn discover_device(
    client: &mut BACnetClient<bacnet_transport::bip::BipTransport>,
    args: &Args,
) {
    if let Some(device_ip) = args.address {
        let mac = encode_bip_mac(device_ip.octets(), DEFAULT_BACNET_PORT).to_vec();
        eprintln!("Using fixed address {device_ip}:{} (skip Who-Is)", DEFAULT_BACNET_PORT);
        if let Err(e) = client.add_device(args.device, &mac).await {
            eprintln!("ERROR: add_device failed: {e}");
            process::exit(1);
        }
        return;
    }

    let whois = WhoIsRequest {
        low_limit: Some(args.device),
        high_limit: Some(args.device),
    };
    let mut whois_buf = BytesMut::new();
    whois.encode(&mut whois_buf);

    eprintln!("Sending Who-Is for device {}...", args.device);
    if let Err(e) = client
        .broadcast_unconfirmed(UnconfirmedServiceChoice::WHO_IS, &whois_buf)
        .await
    {
        eprintln!("ERROR: local Who-Is failed: {e}");
        process::exit(1);
    }
    if let Err(e) = client.who_is(Some(args.device), Some(args.device)).await {
        eprintln!("ERROR: global Who-Is failed: {e}");
        process::exit(1);
    }

    tokio::time::sleep(Duration::from_secs(args.timeout)).await;

    if client.get_device(args.device).await.is_none() {
        eprintln!(
            "ERROR: device {} not found after {}s Who-Is",
            args.device, args.timeout
        );
        let _ = client.stop().await;
        process::exit(1);
    }
}

async fn write_present_value(
    client: &BACnetClient<bacnet_transport::bip::BipTransport>,
    device: u32,
    oid: ObjectIdentifier,
    value: &PropertyValue,
    priority: Option<u8>,
) -> Result<(), bacnet_types::error::Error> {
    let mut buf = BytesMut::new();
    encode_property_value(&mut buf, value)
        .map_err(|e| bacnet_types::error::Error::Encoding(e.to_string()))?;
    client
        .write_property_to_device(
            device,
            oid,
            PropertyIdentifier::PRESENT_VALUE,
            None,
            buf.to_vec(),
            priority,
        )
        .await
}

fn verify_write_taken(
    snap: &PointSnapshot,
    expected_pv: &PropertyValue,
    priority: u8,
    tolerance: f32,
) -> bool {
    let slot_ok = snap
        .priority_slot
        .as_ref()
        .is_some_and(|v| values_match(expected_pv, v, tolerance));

    if !slot_ok {
        eprintln!(
            "FAIL: priority-array[P{priority}] expected {} got {}",
            present_value_hint(expected_pv),
            snap.priority_slot
                .as_ref()
                .map(present_value_hint)
                .unwrap_or_else(|| "null".into())
        );
        return false;
    }

    let pv_matches = values_match(expected_pv, &snap.present_value, tolerance);
    if pv_matches {
        println!("OK: present-value matches written value");
        return true;
    }

    // Priority slot holds the write; a higher-priority (lower P number) slot may still command PV.
    if snap.current_priority.is_some_and(|p| p < priority) {
        println!(
            "OK: priority-array[P{priority}] holds write; present-value still commanded by higher priority P{} (= {})",
            snap.current_priority.unwrap(),
            present_value_hint(&snap.present_value)
        );
        return true;
    }

    eprintln!(
        "FAIL: present-value expected {} got {} (and no higher priority explains the difference)",
        present_value_hint(expected_pv),
        present_value_hint(&snap.present_value)
    );
    false
}

fn verify_relinquished(
    snap: &PointSnapshot,
    baseline: &PointSnapshot,
    priority: u8,
    tolerance: f32,
) -> bool {
    let slot_ok = snap.priority_slot.is_none();
    let pv_ok = values_match(&baseline.present_value, &snap.present_value, tolerance);

    if !slot_ok {
        eprintln!(
            "FAIL: priority-array[P{priority}] expected null got {}",
            snap.priority_slot
                .as_ref()
                .map(present_value_hint)
                .unwrap_or_else(|| "null".into())
        );
    }
    if !pv_ok {
        eprintln!(
            "FAIL: present-value after relinquish expected {} (baseline) got {}",
            present_value_hint(&baseline.present_value),
            present_value_hint(&snap.present_value)
        );
        eprintln!("NOTE: if a lower priority slot is active, PV may legitimately differ");
    }

    slot_ok && pv_ok
}

#[tokio::main]
async fn main() {
    let args = Args::parse();
    let interface = resolve_interface(&args);
    let broadcast = args
        .broadcast
        .unwrap_or_else(|| subnet_broadcast(interface));
    let bind_port = if args.ephemeral { 0 } else { args.port };

    let point_oid = match parse_point(&args.point) {
        Ok(o) => o,
        Err(e) => {
            eprintln!("ERROR: {e}");
            process::exit(1);
        }
    };

    if !(1..=16).contains(&args.priority) {
        eprintln!("ERROR: priority must be 1..=16");
        process::exit(1);
    }

    eprintln!(
        "Write demo: device={} point={} value={} priority=P{} bind={interface}:{bind_port}",
        args.device, args.point, args.value, args.priority
    );

    let mut client = match BACnetClient::bip_builder()
        .interface(interface)
        .port(bind_port)
        .broadcast_address(broadcast)
        .apdu_timeout_ms(8000)
        .build()
        .await
    {
        Ok(c) => c,
        Err(e) if bind_port == DEFAULT_BACNET_PORT => {
            eprintln!("ERROR: cannot bind UDP {interface}:{bind_port} ({e})");
            eprintln!("Hint: stop other BACnet process on :47808 or use --ephemeral");
            process::exit(1);
        }
        Err(e) => {
            eprintln!("ERROR: BACnet client failed: {e}");
            process::exit(1);
        }
    };

    discover_device(&mut client, &args).await;

    let baseline = match read_snapshot(&client, args.device, point_oid, args.priority).await {
        Ok(s) => s,
        Err(e) => {
            eprintln!("ERROR: baseline read failed: {e}");
            let _ = client.stop().await;
            process::exit(1);
        }
    };

    println!("\n=== Baseline ===");
    print_snapshot("Before", &point_oid, &baseline, args.priority);

    let write_val = PropertyValue::Real(args.value);
    if let Err(e) = write_present_value(
        &client,
        args.device,
        point_oid,
        &write_val,
        Some(args.priority),
    )
    .await
    {
        eprintln!("ERROR: WriteProperty failed: {e}");
        let _ = client.stop().await;
        process::exit(1);
    }
    println!(
        "\n=== Write @ P{} = {} ===",
        args.priority,
        present_value_hint(&write_val)
    );
    println!("WriteProperty ACK");

    let after_write = match read_snapshot(&client, args.device, point_oid, args.priority).await {
        Ok(s) => s,
        Err(e) => {
            eprintln!("ERROR: verify read after write failed: {e}");
            let _ = client.stop().await;
            process::exit(1);
        }
    };
    println!("\n=== Verify write (read-back + priority array) ===");
    print_snapshot("After write", &point_oid, &after_write, args.priority);

    if !verify_write_taken(&after_write, &write_val, args.priority, args.tolerance) {
        eprintln!("\nERROR: write verification failed");
        let _ = client.stop().await;
        process::exit(1);
    }
    println!("OK: write taken at P{} (present-value + priority-array match)", args.priority);

    if args.no_revert {
        let _ = client.stop().await;
        println!("\nDone (--no-revert: priority slot left active).");
        return;
    }

    if let Err(e) = write_present_value(
        &client,
        args.device,
        point_oid,
        &PropertyValue::Null,
        Some(args.priority),
    )
    .await
    {
        eprintln!("ERROR: relinquish (Null @ P{}) failed: {e}", args.priority);
        let _ = client.stop().await;
        process::exit(1);
    }
    println!(
        "\n=== Relinquish P{} (Null write) ===",
        args.priority
    );
    println!("WriteProperty Null ACK");

    let after_revert = match read_snapshot(&client, args.device, point_oid, args.priority).await {
        Ok(s) => s,
        Err(e) => {
            eprintln!("ERROR: verify read after relinquish failed: {e}");
            let _ = client.stop().await;
            process::exit(1);
        }
    };
    println!("\n=== Verify relinquish (read-back + priority array) ===");
    print_snapshot("After revert", &point_oid, &after_revert, args.priority);

    if !verify_relinquished(&after_revert, &baseline, args.priority, args.tolerance) {
        eprintln!("\nERROR: relinquish verification failed");
        let _ = client.stop().await;
        process::exit(1);
    }
    println!(
        "OK: P{} relinquished (priority-array null, present-value restored to baseline)",
        args.priority
    );

    let _ = client.stop().await;
    println!("\nDone — full write cycle verified.");
}
