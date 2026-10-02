//! `bacnet tui`: the full-screen terminal UI.
//!
//! Layout of this module tree (see `docs/design/tui.md`):
//!
//! - [`app`]: the TEA core. `App`, `Action` and a pure `update` that returns
//!   `Command`s. No I/O, no transport generics.
//! - [`view`]: rendering, pure functions of `&App`.
//! - [`keymap`]: keys to actions.
//! - [`event_loop`]: the `select!` loop over input, frames, worker events and
//!   signals.
//! - [`worker`]: the only code generic over `TransportPort`. It owns the
//!   client and talks to the UI over bounded channels ([`message`]).
//! - [`terminal`]: the TTY guard, raw mode, the panic hook and signals.
//! - [`log_layer`]: tracing into an in-memory ring for the log pane.
//!
//! This milestone is read-only: it sends discovery requests and nothing that
//! changes a remote device.

mod app;
mod event_loop;
mod keymap;
mod log_layer;
mod message;
mod terminal;
mod view;
mod worker;

#[cfg(test)]
mod tests;

use std::io::Write as _;
use std::net::Ipv4Addr;
use std::path::Path;
use std::sync::Mutex;
use std::time::Duration;

use ratatui::crossterm::event::EventStream;
use tokio::sync::mpsc;

use self::app::picker::Picker;
use self::app::{App, AppConfig};
use self::event_loop::LoopIo;
use self::log_layer::{LogRing, RingLayer, LOG_CAPACITY};
use self::terminal::Signals;
use self::worker::session::{self, ConnectPlan, TransportKind};
use self::worker::{EventSink, COMMAND_CHANNEL_CAPACITY, EVENT_CHANNEL_CAPACITY};
use crate::args::{Cli, Command};
use crate::core::interfaces::list_ipv4_interfaces;
use crate::transport::TransportArgs;

/// How long to wait for the worker to stop the client on exit.
const STOP_TIMEOUT: Duration = Duration::from_secs(3);

/// Run `bacnet tui`. Returns only on a clean quit; errors are printed after
/// the terminal is restored and the process exits non-zero.
pub(crate) async fn run(cli: Cli) -> crate::CliResult {
    if let Err(hint) = terminal::check_terminal() {
        eprintln!("{hint}");
        std::process::exit(1);
    }
    let (fps, log_file) = match &cli.command {
        Some(Command::Tui { fps, log_file }) => (*fps, log_file.clone()),
        _ => (20, None),
    };
    let kind = if cli.sc {
        TransportKind::Sc
    } else if cli.ipv6 {
        TransportKind::Bip6
    } else {
        TransportKind::Bip
    };
    if kind == TransportKind::Sc && !cfg!(feature = "sc-tls") {
        eprintln!("Error: BACnet/SC requires the 'sc-tls' feature. Rebuild with: cargo install bacnet-cli --features sc-tls");
        std::process::exit(1);
    }

    let log = LogRing::new(LOG_CAPACITY);
    if let Err(error) = init_tracing(cli.verbose, log_file.as_deref(), &log) {
        eprintln!("Error: {error}");
        std::process::exit(1);
    }

    let (interface, broadcast, picker) = choose_interface(&cli, kind, &log);
    let args = match TransportArgs::from_cli(&cli, interface, broadcast) {
        Ok(args) => args,
        Err(error) => {
            eprintln!("Error: {error}");
            std::process::exit(1);
        }
    };
    let plan = ConnectPlan {
        kind,
        args,
        await_interface: picker.is_some(),
    };
    let color = std::env::var_os("NO_COLOR").is_none_or(|v| v.is_empty());
    let mut app = Box::new(App::new(
        AppConfig {
            transport: kind.label(),
            style: kind.style(),
            color,
            picker,
            now: tokio::time::Instant::now().into_std(),
        },
        log,
    ));

    let (sink, events) = EventSink::channel(EVENT_CHANNEL_CAPACITY);
    let dropped = sink.dropped_counter();
    let (commands, command_rx) = mpsc::channel(COMMAND_CHANNEL_CAPACITY);
    let signals = Signals::install()?;
    let worker = session::spawn(plan, sink, command_rx);

    let mut terminal = terminal::enter()?;
    let mut io = LoopIo {
        input: EventStream::new(),
        events,
        commands,
        dropped,
        fps,
        signals,
    };
    let result = Box::pin(event_loop::run(&mut terminal, &mut app, &mut io)).await;
    // Leave raw mode first: `Terminal`'s drop can report a cursor error on stderr.
    terminal::restore();
    drop(terminal);

    // Closing the command channel tells the worker to stop the client.
    drop(io);
    if tokio::time::timeout(STOP_TIMEOUT, worker).await.is_err() {
        tracing::warn!("the network worker did not stop in time");
    }
    let error = match result {
        Ok(_) => app.exit_error.take(),
        Err(error) => Some(error.to_string()),
    };
    if let Some(error) = error {
        // stderr may be gone (SIGHUP), so a failed write is not a panic.
        let _ = writeln!(std::io::stderr(), "Error: {error}");
        std::process::exit(1);
    }
    Ok(())
}

/// The BACnet/IP interface: `-i`, the only one there is, or the picker.
fn choose_interface(
    cli: &Cli,
    kind: TransportKind,
    log: &LogRing,
) -> (Ipv4Addr, Ipv4Addr, Option<Picker>) {
    if let Some(interface) = cli.interface {
        return (interface, cli.broadcast, None);
    }
    if kind != TransportKind::Bip {
        return (Ipv4Addr::UNSPECIFIED, cli.broadcast, None);
    }
    let mut interfaces = list_ipv4_interfaces();
    match interfaces.len() {
        0 => {
            log.info("No network interfaces found; binding to 0.0.0.0.");
            (Ipv4Addr::UNSPECIFIED, Ipv4Addr::BROADCAST, None)
        }
        1 => {
            let only = interfaces.remove(0);
            log.info(format!(
                "Using interface {} ({}, broadcast {}).",
                only.name, only.ip, only.broadcast
            ));
            (only.ip, only.broadcast, None)
        }
        _ => (
            Ipv4Addr::UNSPECIFIED,
            cli.broadcast,
            Some(Picker::new(interfaces)),
        ),
    }
}

/// Route tracing to the log pane's ring and, with `--log-file`, to a file.
/// Nothing goes to stdout or stderr while the terminal is in raw mode.
fn init_tracing(verbosity: u8, log_file: Option<&Path>, ring: &LogRing) -> Result<(), String> {
    use tracing_subscriber::layer::SubscriberExt;
    use tracing_subscriber::util::SubscriberInitExt;
    use tracing_subscriber::EnvFilter;

    let level = match verbosity {
        0 => "info",
        1 => "debug",
        _ => "trace",
    };
    let file_layer = match log_file {
        Some(path) => {
            let file = std::fs::OpenOptions::new()
                .create(true)
                .append(true)
                .open(path)
                .map_err(|e| format!("cannot open --log-file {}: {e}", path.display()))?;
            Some(
                tracing_subscriber::fmt::layer()
                    .with_ansi(false)
                    .with_target(false)
                    .with_writer(Mutex::new(file)),
            )
        }
        None => None,
    };
    tracing_subscriber::registry()
        .with(EnvFilter::new(level))
        .with(RingLayer::new(ring.clone()))
        .with(file_layer)
        .try_init()
        .map_err(|e| e.to_string())
}
