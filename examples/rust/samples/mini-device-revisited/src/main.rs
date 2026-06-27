//! Mini BACnet device — Rust port of BACpypes3 `mini-device-revisited.py`.
//!
//! Exposes four points on a BACnet/IP device:
//! - analogValue:1  read-only (simulated ramp)
//! - binaryValue:1  read-only (simulated active/inactive)
//! - analogValue:2  commandable (priority array)
//! - binaryValue:2  commandable (priority array)
//!
//! Bind UDP on 0.0.0.0 (rusty-bacnet-mcp style) with a directed broadcast so
//! subnet Who-Is reaches the socket on Linux; advertise the NIC IP in I-Am.

use std::env;
use std::net::{Ipv4Addr, SocketAddrV4, UdpSocket as StdUdpSocket};
use std::process;
use std::sync::Arc;
use std::time::Duration;

use bytes::{Bytes, BytesMut};
use socket2::{Domain, Protocol, Socket, Type};

use bacnet_client::client::BACnetClient;
use bacnet_encoding::apdu::{encode_apdu, Apdu, UnconfirmedRequest as UnconfirmedRequestPdu};
use bacnet_encoding::npdu::{encode_npdu, Npdu};
use bacnet_encoding::primitives::decode_application_value;
use bacnet_objects::analog::AnalogValueObject;
use bacnet_objects::binary::BinaryValueObject;
use bacnet_objects::database::ObjectDatabase;
use bacnet_objects::device::{DeviceConfig, DeviceObject};
use bacnet_objects::traits::BACnetObject;
use bacnet_server::server::BACnetServer;
use bacnet_services::who_is::IAmRequest;
use bacnet_transport::bip::DEFAULT_BACNET_PORT;
use bacnet_transport::bvll::{encode_bip_mac, encode_bvll};
use bacnet_types::enums::{
    BvlcFunction, NetworkPriority, ObjectType, PropertyIdentifier, Segmentation,
    UnconfirmedServiceChoice,
};
use bacnet_types::primitives::{ObjectIdentifier, PropertyValue};
use clap::Parser;
use tokio::sync::RwLock;
use tracing::{debug, info, warn};

const UNITS_DEGF: u32 = 62; // degreesFahrenheit
const SIM_INTERVAL_SECS: u64 = 5;
const VENDOR_ID: u16 = 999;
const MAX_APDU_LENGTH: u32 = 1476;
const DEFAULT_IAM_INTERVAL_SECS: u64 = 60;

/// Socket bind address (always 0.0.0.0) vs NIC IP advertised in I-Am / MAC.
#[derive(Clone, Copy)]
struct NetworkConfig {
    device_ip: Ipv4Addr,
    socket_bind: Ipv4Addr,
    broadcast: Ipv4Addr,
}

#[derive(Parser, Debug)]
#[command(
    name = "mini-device-revisited",
    about = "Minimal rusty-bacnet device (BACpypes3 mini-device port)"
)]
struct Args {
    /// BACnet device object name
    #[arg(long, default_value = "BensServerTest")]
    name: String,

    /// BACnet device instance number
    #[arg(long, default_value_t = 3456)]
    instance: u32,

    /// Local NIC IPv4 (advertised in I-Am). UDP binds 0.0.0.0 for discovery.
    #[arg(long)]
    address: Option<Ipv4Addr>,

    /// UDP port (default BACnet 47808 / 0xBAC0)
    #[arg(long, default_value_t = DEFAULT_BACNET_PORT)]
    port: u16,

    /// Directed broadcast for the subnet (default: derive /24 from --address)
    #[arg(long)]
    broadcast: Option<Ipv4Addr>,

    /// Broadcast I-Am every N seconds (0 = disable). Helps network scanners.
    #[arg(long, default_value_t = DEFAULT_IAM_INTERVAL_SECS)]
    announce_interval: u64,

    /// Verbose debug logging (bacnet stack + incoming Who-Is/I-Am)
    #[arg(long)]
    debug: bool,

    /// Maximum tracing (UDP recv + NPDU/APDU decode)
    #[arg(long)]
    trace: bool,

    /// Skip startup Who-Is self-check (avoids extra client on same NIC)
    #[arg(long)]
    skip_self_check: bool,

    /// Deprecated: breaks Who-Is (SO_REUSEPORT steals packets). Use --trace instead.
    #[arg(long, hide = true)]
    log_packets: bool,
}

fn init_logging(args: &Args) {
    let filter = if args.trace {
        "trace,mini_device_revisited=debug,bacnet_server=trace,bacnet_transport=trace,bacnet_network=trace,bacnet_services=trace,bacnet_client=trace"
    } else if args.debug {
        "debug,mini_device_revisited=debug,bacnet_server=debug,bacnet_transport=debug,bacnet_network=debug,bacnet_services=debug"
    } else {
        "info,mini_device_revisited=info,bacnet_server=info,bacnet_transport=warn"
    };
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new(filter)),
        )
        .with_target(true)
        .with_thread_ids(false)
        .init();
}

fn log_discovery_help(net: &NetworkConfig, port: u16, instance: u32) {
    info!("--- Discovery ---");
    info!(
        "UDP bind={}:{} (all interfaces) device_ip={} broadcast={}",
        net.socket_bind, port, net.device_ip, net.broadcast
    );
    info!(
        "Scan from bench: ~/rs-bacnet-testers/whois-scan/run.sh  (stop this app first — both need :47808)"
    );
    info!(
        "Manual add: {}:{} device ID {instance}",
        net.device_ip, port
    );
    info!("Same-host whois-scan usually will not list this device (rusty-bacnet ignores same IP:47808); use Yabe from another PC on the subnet");
    info!("Debug: --debug or --trace (not --log-packets; that breaks Who-Is)");
}

fn subnet_broadcast(ip: Ipv4Addr) -> Ipv4Addr {
    let octets = ip.octets();
    Ipv4Addr::new(octets[0], octets[1], octets[2], 255)
}

fn detect_enp3s0_address() -> Option<Ipv4Addr> {
    let output = std::process::Command::new("ip")
        .args(["-4", "addr", "show", "dev", "enp3s0"])
        .output()
        .ok()?;
    let text = String::from_utf8_lossy(&output.stdout);
    for line in text.lines() {
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

fn die_on_bind_error(msg: impl AsRef<str>) -> ! {
    eprintln!("ERROR: {}", msg.as_ref());
    process::exit(1);
}

/// Stop other instances of this binary and anything holding the BACnet UDP port.
fn kill_prior_listeners(port: u16) {
    let my_pid = process::id();
    let my_exe = env::current_exe().ok();

    if let Ok(entries) = std::fs::read_dir("/proc") {
        for entry in entries.flatten() {
            let pid = match entry.file_name().to_string_lossy().parse::<u32>() {
                Ok(p) => p,
                Err(_) => continue,
            };
            if pid == my_pid {
                continue;
            }
            let exe = std::fs::read_link(format!("/proc/{pid}/exe")).ok();
            if exe.as_ref() == my_exe.as_ref() {
                info!("Stopping prior mini-device-revisited pid={pid}");
                let _ = process::Command::new("kill")
                    .args(["-TERM", &pid.to_string()])
                    .output();
            }
        }
    }

    let port_spec = format!("{port}/udp");
    if process::Command::new("fuser")
        .arg(&port_spec)
        .output()
        .map(|o| !o.stdout.is_empty() || !o.stderr.is_empty())
        .unwrap_or(false)
    {
        info!("Releasing UDP port {port} (fuser -k)");
        let _ = process::Command::new("fuser")
            .args(["-k", &port_spec])
            .output();
    }

    std::thread::sleep(Duration::from_millis(750));
}

/// Fail fast if we cannot bind the requested address (NIC IP or 0.0.0.0).
fn verify_udp_bind(bind_ip: Ipv4Addr, port: u16) {
    let socket = match Socket::new(Domain::IPV4, Type::DGRAM, Some(Protocol::UDP)) {
        Ok(s) => s,
        Err(e) => die_on_bind_error(format!("cannot create UDP socket for {bind_ip}:{port}: {e}")),
    };
    if let Err(e) = socket.set_reuse_address(true) {
        die_on_bind_error(format!(
            "cannot set SO_REUSEADDR on {bind_ip}:{port}: {e}"
        ));
    }
    if let Err(e) = socket.bind(&SocketAddrV4::new(bind_ip, port).into()) {
        die_on_bind_error(format!(
            "cannot bind UDP {bind_ip}:{port} — port in use or address not available on this host ({e})"
        ));
    }
    info!("Pre-flight bind OK on {bind_ip}:{port}");
}

fn resolve_device_ip(args: &Args) -> Ipv4Addr {
    if let Some(ip) = args.address {
        return ip;
    }
    if let Some(ip) = detect_enp3s0_address() {
        info!("auto-detected NIC address on enp3s0: {ip}");
        return ip;
    }
    warn!("no --address and enp3s0 not found; device IP unknown until stack starts");
    Ipv4Addr::UNSPECIFIED
}

fn resolve_network_config(args: &Args) -> NetworkConfig {
    let device_ip = resolve_device_ip(args);
    let broadcast = args
        .broadcast
        .unwrap_or_else(|| {
            if device_ip.is_unspecified() {
                Ipv4Addr::BROADCAST
            } else {
                subnet_broadcast(device_ip)
            }
        });
    NetworkConfig {
        device_ip,
        socket_bind: Ipv4Addr::UNSPECIFIED,
        broadcast,
    }
}

fn verify_server_mac(device_ip: Ipv4Addr, port: u16, mac: &[u8]) {
    if device_ip.is_unspecified() {
        return;
    }
    let expected = encode_bip_mac(device_ip.octets(), port);
    if mac == expected.as_slice() {
        info!(
            "Device MAC matches NIC — {:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
            mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]
        );
    } else {
        warn!(
            "Device MAC {:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x} != expected {}:{} — check routing/default interface",
            mac[0], mac[1], mac[2], mac[3], mac[4], mac[5],
            device_ip, port
        );
    }
}

fn build_iam_broadcast_frame(instance: u32) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    let device_oid = ObjectIdentifier::new(ObjectType::DEVICE, instance)?;
    let i_am = IAmRequest {
        object_identifier: device_oid,
        max_apdu_length: MAX_APDU_LENGTH,
        segmentation_supported: Segmentation::NONE,
        vendor_id: VENDOR_ID,
    };
    let mut service_buf = BytesMut::new();
    i_am.encode(&mut service_buf);

    let pdu = Apdu::UnconfirmedRequest(UnconfirmedRequestPdu {
        service_choice: UnconfirmedServiceChoice::I_AM,
        service_request: service_buf.freeze(),
    });
    let mut apdu_buf = BytesMut::new();
    encode_apdu(&mut apdu_buf, &pdu)?;

    let npdu = Npdu {
        is_network_message: false,
        expecting_reply: false,
        priority: NetworkPriority::NORMAL,
        destination: None,
        source: None,
        payload: Bytes::from(apdu_buf.to_vec()),
        ..Npdu::default()
    };
    let mut npdu_buf = BytesMut::new();
    encode_npdu(&mut npdu_buf, &npdu)?;

    let mut frame = BytesMut::new();
    encode_bvll(
        &mut frame,
        BvlcFunction::ORIGINAL_BROADCAST_NPDU,
        &npdu_buf,
    )?;
    Ok(frame.to_vec())
}

fn send_iam_broadcast(
    net: &NetworkConfig,
    port: u16,
    instance: u32,
) -> Result<(), Box<dyn std::error::Error>> {
    let frame = build_iam_broadcast_frame(instance)?;
    let socket = StdUdpSocket::bind(SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, 0))?;
    socket.set_broadcast(true)?;
    let dest = SocketAddrV4::new(net.broadcast, port);
    socket.send_to(&frame, dest)?;
    debug!(
        "I-Am broadcast sent for device {instance} -> {dest} ({} bytes)",
        frame.len()
    );
    Ok(())
}

async fn iam_announcement_task(net: NetworkConfig, port: u16, instance: u32, interval_secs: u64) {
    if interval_secs == 0 {
        return;
    }
    loop {
        tokio::time::sleep(Duration::from_secs(interval_secs)).await;
        match send_iam_broadcast(&net, port, instance) {
            Ok(()) => info!(
                "I-Am announcement: device {instance} on {}:{} (broadcast {}:{port})",
                net.device_ip, port, net.broadcast
            ),
            Err(e) => warn!("I-Am announcement failed: {e}"),
        }
    }
}

fn build_database(args: &Args) -> Result<ObjectDatabase, Box<dyn std::error::Error>> {
    let mut db = ObjectDatabase::new();
    let device_oid = ObjectIdentifier::new(ObjectType::DEVICE, args.instance)?;

    // --- Read-only analogValue:1 ---
    let mut read_only_av = AnalogValueObject::new(1, "read-only-av", UNITS_DEGF)?;
    read_only_av.set_description("Simulated Read-Only Analog Value");
    read_only_av.set_present_value(4.0);
    read_only_av.write_property(
        PropertyIdentifier::COV_INCREMENT,
        None,
        PropertyValue::Real(1.0),
        None,
    )?;
    db.add(Box::new(read_only_av))?;

    // --- Read-only binaryValue:1 ---
    let mut read_only_bv = BinaryValueObject::new(1, "read-only-bv")?;
    read_only_bv.set_description("Simulated Read-Only Binary Value");
    read_only_bv.write_property(
        PropertyIdentifier::PRESENT_VALUE,
        None,
        PropertyValue::Enumerated(1), // active
        None,
    )?;
    db.add(Box::new(read_only_bv))?;

    // --- Commandable analogValue:2 ---
    let mut commandable_av = AnalogValueObject::new(2, "commandable-av", UNITS_DEGF)?;
    commandable_av.set_description("Commandable Analog Value (Simulated)");
    commandable_av.set_present_value(0.0);
    commandable_av.write_property(
        PropertyIdentifier::COV_INCREMENT,
        None,
        PropertyValue::Real(1.0),
        None,
    )?;
    db.add(Box::new(commandable_av))?;

    // --- Commandable binaryValue:2 ---
    let mut commandable_bv = BinaryValueObject::new(2, "commandable-bv")?;
    commandable_bv.set_description("Commandable Binary Value (Simulated)");
    commandable_bv.write_property(
        PropertyIdentifier::PRESENT_VALUE,
        None,
        PropertyValue::Enumerated(0), // inactive
        None,
    )?;
    db.add(Box::new(commandable_bv))?;

    // Device object-list must enumerate all objects — scanners (Yabe, Contemporary Controls)
    // walk this property to populate their object tree.
    let mut point_oids = db.list_objects();
    point_oids.sort_by_key(|o| (o.object_type().to_raw(), o.instance_number()));
    let mut object_list = vec![device_oid];
    object_list.extend(point_oids);

    let mut device = DeviceObject::new(DeviceConfig {
        instance: args.instance,
        name: args.name.clone(),
        vendor_name: "rs-bacnet-testers".into(),
        vendor_id: VENDOR_ID,
        model_name: "mini-device-revisited".into(),
        application_software_version: env!("CARGO_PKG_VERSION").into(),
        ..DeviceConfig::default()
    })?;
    device.set_object_list(object_list);
    db.add(Box::new(device))?;

    Ok(db)
}

async fn simulation_task(db: Arc<RwLock<ObjectDatabase>>) {
    let av_oid = ObjectIdentifier::new(ObjectType::ANALOG_VALUE, 1).expect("av:1");
    let bv_oid = ObjectIdentifier::new(ObjectType::BINARY_VALUE, 1).expect("bv:1");

    let samples: [(bool, f32); 4] = [
        (true, 1.0),
        (false, 2.0),
        (true, 3.0),
        (false, 4.0),
    ];
    let mut idx = 0usize;

    loop {
        tokio::time::sleep(Duration::from_secs(SIM_INTERVAL_SECS)).await;
        let (active, av_val) = samples[idx];
        idx = (idx + 1) % samples.len();

        let mut db = db.write().await;
        if let Some(obj) = db.get_mut(&av_oid) {
            let _ = obj.write_property(
                PropertyIdentifier::PRESENT_VALUE,
                None,
                PropertyValue::Real(av_val),
                None,
            );
        }
        if let Some(obj) = db.get_mut(&bv_oid) {
            let bv_val = if active { 1 } else { 0 };
            let _ = obj.write_property(
                PropertyIdentifier::PRESENT_VALUE,
                None,
                PropertyValue::Enumerated(bv_val),
                None,
            );
        }
        debug!(
            "sim tick: read-only-av={av_val} read-only-bv={}",
            if active { "active" } else { "inactive" }
        );
    }
}

async fn discovery_self_check(
    net: &NetworkConfig,
    port: u16,
    device_instance: u32,
    device_name: &str,
) {
    let server_mac: Vec<u8> = {
        let o = net.device_ip.octets();
        vec![o[0], o[1], o[2], o[3], (port >> 8) as u8, (port & 0xff) as u8]
    };

    let mut client = match BACnetClient::bip_builder()
        .interface(net.device_ip)
        .port(0)
        .broadcast_address(net.broadcast)
        .build()
        .await
    {
        Ok(c) => c,
        Err(e) => {
            warn!("discovery self-check skipped (client build failed): {e}");
            return;
        }
    };

    let device_oid = match ObjectIdentifier::new(ObjectType::DEVICE, device_instance) {
        Ok(o) => o,
        Err(e) => {
            warn!("discovery self-check skipped (bad device oid): {e}");
            let _ = client.stop().await;
            return;
        }
    };

    match client
        .read_property(
            &server_mac,
            device_oid,
            PropertyIdentifier::OBJECT_NAME,
            None,
        )
        .await
    {
        Ok(ack) => {
            if let Ok((PropertyValue::CharacterString(name), _)) =
                decode_application_value(&ack.property_value, 0)
            {
                info!("unicast self-check OK — object-name={name:?}");
            } else {
                info!("unicast self-check OK — device responded");
            }
        }
        Err(e) => warn!("unicast self-check failed: {e}"),
    }

    if let Err(e) = client.who_is(None, None).await {
        warn!("Who-Is self-check failed: {e}");
        let _ = client.stop().await;
        return;
    }
    tokio::time::sleep(Duration::from_millis(1500)).await;
    let devices = client.discovered_devices().await;
    let _ = client.stop().await;

    if devices
        .iter()
        .any(|d| d.object_identifier.instance_number() == device_instance)
    {
        info!(
            "Who-Is self-check OK — device {device_instance} visible on broadcast"
        );
    } else if device_name.is_empty() {
        warn!(
            "Who-Is self-check: device {device_instance} not seen (broadcast may be filtered on this NIC/subnet)"
        );
    } else {
        warn!(
            "Who-Is self-check: device {device_instance} not seen in {} I-Am response(s) — unicast OK; if Yabe cannot discover, check subnet broadcast / firewall",
            devices.len()
        );
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args = Args::parse();
    init_logging(&args);

    if args.log_packets {
        warn!("--log-packets is disabled (SO_REUSEPORT steals Who-Is from the server); use --trace");
    }

    let net = resolve_network_config(&args);

    info!(
        "Starting mini-device-revisited: name={} instance={} device_ip={} bind={}:{} broadcast={}",
        args.name, args.instance, net.device_ip, net.socket_bind, args.port, net.broadcast
    );

    kill_prior_listeners(args.port);
    verify_udp_bind(net.socket_bind, args.port);

    let db = build_database(&args)?;
    info!(
        "Object database: {} objects (device + 4 points in object-list)",
        db.len()
    );

    let mut server = match BACnetServer::bip_builder()
        .interface(net.socket_bind)
        .port(args.port)
        .broadcast_address(net.broadcast)
        .database(db)
        .build()
        .await
    {
        Ok(s) => s,
        Err(e) => die_on_bind_error(format!(
            "BACnet server failed to bind {}:{} — {e}",
            net.socket_bind, args.port
        )),
    };

    let mac = server.local_mac();
    verify_server_mac(net.device_ip, args.port, mac);
    info!(
        "BACnet/IP server up — MAC {:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x} (Who-Is/I-Am enabled, vendor {VENDOR_ID})",
        mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]
    );
    info!(
        "Points: AV:1 read-only, BV:1 read-only, AV:2 commandable, BV:2 commandable"
    );
    info!("Simulation interval: {}s (read-only points only)", SIM_INTERVAL_SECS);
    log_discovery_help(&net, args.port, args.instance);

    // Immediate I-Am so passive scanners see us without waiting for Who-Is.
    if args.announce_interval > 0 {
        if let Err(e) = send_iam_broadcast(&net, args.port, args.instance) {
            warn!("startup I-Am broadcast failed: {e}");
        } else {
            info!("startup I-Am broadcast sent for device {}", args.instance);
        }
        let net_ann = net;
        tokio::spawn(iam_announcement_task(
            net_ann,
            args.port,
            args.instance,
            args.announce_interval,
        ));
    }

    let db_arc = Arc::clone(server.database());
    tokio::spawn(simulation_task(db_arc));

    if args.skip_self_check {
        info!("Skipping startup Who-Is self-check (--skip-self-check)");
    } else {
        discovery_self_check(&net, args.port, args.instance, &args.name).await;
    }

    info!(
        "Listening for Who-Is on UDP {}:{} (device {}) — Ctrl+C to stop.",
        net.socket_bind, args.port, net.device_ip
    );
    tokio::signal::ctrl_c().await?;
    info!("Shutting down...");
    let _ = server.stop().await;
    Ok(())
}
