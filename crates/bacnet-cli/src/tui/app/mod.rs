//! The TEA core: one [`App`] state, one [`Action`] enum and [`update`], which
//! changes the state and returns [`Command`]s for the worker.
//!
//! `update` does no I/O: no terminal, no network, no clock. Time arrives in
//! [`Action::Tick`], so the whole state machine is testable without a
//! terminal or a transport.

pub(crate) mod devices;
pub(crate) mod picker;
pub(crate) mod whois;

use std::time::{Duration, Instant};

use self::devices::{DeviceTable, Duplicates, Movement};
use self::picker::{Picker, PickerKey};
use self::whois::{FormKey, FormOutcome, WhoIsForm};
use super::log_layer::LogRing;
use super::message::{AddressStyle, Command, OpId, OpOutcome, WhoIsSpec, WorkerEvent};

/// A second Ctrl-C within this window quits.
pub(crate) const CTRL_C_WINDOW: Duration = Duration::from_secs(2);

/// How long a status message stays in the footer.
const FLASH_FOR: Duration = Duration::from_secs(4);

/// State of the link to the network.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Link {
    /// Waiting for the user to pick an interface.
    Picking,
    /// Building the client.
    Connecting,
    /// The client is up.
    Up {
        /// Local address.
        local: String,
    },
    /// Building the client failed.
    Failed(String),
}

/// The modal on top of the screen, if any.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Overlay {
    /// Nothing.
    None,
    /// Key help.
    Help,
    /// The Who-Is form.
    WhoIs(WhoIsForm),
    /// The interface picker.
    Picker(Picker),
}

/// Progress of the current operation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum OpState {
    /// Handed to the worker.
    Sending,
    /// Sent; replies are expected until `until`.
    Listening {
        /// End of the listen window.
        until: Instant,
    },
    /// The listen window ran out.
    Done,
    /// Cancelled.
    Cancelled,
    /// Sending failed.
    Failed(String),
}

/// The latest Who-Is the user started.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Operation {
    /// Its id.
    pub(crate) id: OpId,
    /// The request.
    pub(crate) spec: WhoIsSpec,
    /// I-Am answers in range received while it ran.
    pub(crate) replies: usize,
    /// Progress.
    pub(crate) state: OpState,
}

impl Operation {
    /// True while sending or listening.
    pub(crate) fn running(&self) -> bool {
        matches!(self.state, OpState::Sending | OpState::Listening { .. })
    }
}

/// A short message in the footer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Flash {
    /// The text.
    pub(crate) text: String,
    /// When it disappears.
    pub(crate) until: Instant,
}

/// A key while the filter line is open.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum FilterKey {
    /// Type a character.
    Char(char),
    /// Delete the last character.
    Backspace,
    /// Close the line and keep the filter.
    Commit,
    /// Close the line and clear the filter.
    Clear,
}

/// Everything that can change the state.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Action {
    /// A frame interval elapsed.
    Tick {
        /// Current time.
        now: Instant,
        /// Worker events dropped so far.
        dropped: u64,
        /// The log ring's generation.
        log_generation: u64,
    },
    /// The terminal changed size.
    Resize,
    /// Leave the TUI.
    Quit,
    /// Ctrl-C: cancel, or quit on a second press.
    CtrlC,
    /// Esc: close, clear or dismiss.
    Escape,
    /// Show or hide the help overlay.
    ToggleHelp,
    /// Show or hide the log pane.
    ToggleLog,
    /// Open the Who-Is form.
    OpenWhoIs,
    /// Move the table selection.
    Move(Movement),
    /// Next sort column.
    CycleSort,
    /// Flip the sort direction.
    ReverseSort,
    /// Open the filter line.
    StartFilter,
    /// A key on the filter line.
    Filter(FilterKey),
    /// A key in the Who-Is form.
    Form(FormKey),
    /// A key in the interface picker.
    Picker(PickerKey),
    /// A message from the worker.
    Worker(WorkerEvent),
}

/// What [`App::new`] needs from the command line and the environment.
pub(crate) struct AppConfig {
    /// `BIP`, `BIP6` or `SC`.
    pub(crate) transport: &'static str,
    /// How the transport's addresses look.
    pub(crate) style: AddressStyle,
    /// False when `NO_COLOR` is set.
    pub(crate) color: bool,
    /// Interfaces to pick from, when BACnet/IP has no `-i`.
    pub(crate) picker: Option<Picker>,
    /// Start time.
    pub(crate) now: Instant,
}

/// The whole UI state.
pub(crate) struct App {
    /// `BIP`, `BIP6` or `SC`.
    pub(crate) transport: &'static str,
    /// Address style for the form's target field.
    pub(crate) style: AddressStyle,
    /// Use colour.
    pub(crate) color: bool,
    /// Link state.
    pub(crate) link: Link,
    /// The device table.
    pub(crate) devices: DeviceTable,
    /// Instances claimed by more than one address.
    pub(crate) duplicates: Duplicates,
    /// The open modal.
    pub(crate) overlay: Overlay,
    /// The filter line is open.
    pub(crate) filter_editing: bool,
    /// The log pane is shown.
    pub(crate) show_log: bool,
    /// The current or last Who-Is.
    pub(crate) op: Option<Operation>,
    last_spec: Option<WhoIsSpec>,
    next_op: OpId,
    /// Footer message.
    pub(crate) flash: Option<Flash>,
    ctrl_c_at: Option<Instant>,
    epoch: Instant,
    /// Time of the last tick.
    pub(crate) now: Instant,
    /// Worker events dropped because the UI fell behind.
    pub(crate) dropped: u64,
    /// Recent log lines.
    pub(crate) log: LogRing,
    log_generation: u64,
    /// Set when the user quits.
    pub(crate) quit: bool,
    /// Why the TUI ended, if it was an error.
    pub(crate) exit_error: Option<String>,
    /// Exit status to use with `exit_error`; `None` means 1.
    pub(crate) exit_code: Option<i32>,
    /// The screen needs a redraw.
    pub(crate) dirty: bool,
}

impl App {
    /// Initial state.
    pub(crate) fn new(config: AppConfig, log: LogRing) -> Self {
        let (link, overlay) = match config.picker {
            Some(picker) => (Link::Picking, Overlay::Picker(picker)),
            None => (Link::Connecting, Overlay::None),
        };
        let log_generation = log.generation();
        Self {
            transport: config.transport,
            style: config.style,
            color: config.color,
            link,
            devices: DeviceTable::default(),
            duplicates: Duplicates::default(),
            overlay,
            filter_editing: false,
            show_log: false,
            op: None,
            last_spec: None,
            next_op: 0,
            flash: None,
            ctrl_c_at: None,
            epoch: config.now,
            now: config.now,
            dropped: 0,
            log,
            log_generation,
            quit: false,
            exit_error: None,
            exit_code: None,
            dirty: true,
        }
    }

    /// Rebuild derived state (the visible table order) before drawing.
    pub(crate) fn settle(&mut self) {
        self.devices.settle();
    }

    /// End the TUI with an error, keeping the first reason if there are two.
    pub(crate) fn fail(&mut self, error: impl Into<String>, code: i32) {
        if self.exit_error.is_none() {
            self.exit_error = Some(error.into());
            self.exit_code = Some(code);
        }
        self.quit = true;
    }

    /// True while a Who-Is is sending or listening.
    pub(crate) fn op_running(&self) -> bool {
        self.op.as_ref().is_some_and(Operation::running)
    }

    fn flash(&mut self, text: impl Into<String>, lasts: Duration) {
        self.flash = Some(Flash {
            text: text.into(),
            until: self.now + lasts,
        });
    }

    fn running_op_mut(&mut self, id: OpId) -> Option<&mut Operation> {
        self.op.as_mut().filter(|op| op.id == id && op.running())
    }

    fn tick(&mut self, now: Instant, dropped: u64, log_generation: u64) {
        let second = |t: Instant| t.saturating_duration_since(self.epoch).as_secs();
        // Ages and countdowns change once a second.
        if second(now) != second(self.now) && (!self.devices.is_empty() || self.op_running()) {
            self.dirty = true;
        }
        self.now = now;
        if dropped != self.dropped {
            self.dropped = dropped;
            self.dirty = true;
        }
        if log_generation != self.log_generation {
            self.log_generation = log_generation;
            self.dirty |= self.show_log;
        }
        if self.flash.as_ref().is_some_and(|f| now >= f.until) {
            self.flash = None;
            self.dirty = true;
        }
        if self
            .ctrl_c_at
            .is_some_and(|t| now.saturating_duration_since(t) >= CTRL_C_WINDOW)
        {
            self.ctrl_c_at = None;
        }
    }

    fn ctrl_c(&mut self, out: &mut Vec<Command>) {
        let now = self.now;
        if self
            .ctrl_c_at
            .is_some_and(|t| now.saturating_duration_since(t) < CTRL_C_WINDOW)
        {
            self.quit = true;
            return;
        }
        if matches!(self.link, Link::Picking | Link::Connecting) {
            // Starting up is the only operation; cancelling it means leaving.
            self.quit = true;
            return;
        }
        self.ctrl_c_at = Some(now);
        let cancelled = if self.overlay != Overlay::None {
            self.overlay = Overlay::None;
            Some("Closed")
        } else if self.filter_editing {
            self.filter_editing = false;
            Some("Closed the filter")
        } else if let Some(op) = self.op.as_mut().filter(|op| op.running()) {
            op.state = OpState::Cancelled;
            out.push(Command::Cancel { op: op.id });
            Some("Cancelled the Who-Is")
        } else {
            None
        };
        let text = match cancelled {
            Some(what) => format!("{what}. Press Ctrl-C again to quit."),
            None => "Press Ctrl-C again, or q, to quit.".to_string(),
        };
        self.flash(text, CTRL_C_WINDOW);
    }

    fn escape(&mut self) {
        match self.overlay {
            Overlay::Picker(_) => self.quit = true,
            Overlay::Help | Overlay::WhoIs(_) => self.overlay = Overlay::None,
            Overlay::None if !self.devices.filter().is_empty() => {
                self.devices.clear_filter();
                self.devices.settle();
            }
            Overlay::None => self.flash = None,
        }
    }

    fn open_who_is(&mut self) {
        if !matches!(self.link, Link::Up { .. }) {
            self.flash("Not connected yet.", FLASH_FOR);
            return;
        }
        let form = self
            .last_spec
            .as_ref()
            .map(WhoIsForm::from_spec)
            .unwrap_or_default();
        self.overlay = Overlay::WhoIs(form);
    }

    fn filter_key(&mut self, key: FilterKey) {
        match key {
            FilterKey::Char(ch) => self.devices.push_filter(ch),
            FilterKey::Backspace => self.devices.pop_filter(),
            FilterKey::Commit => self.filter_editing = false,
            FilterKey::Clear => {
                self.devices.clear_filter();
                self.filter_editing = false;
            }
        }
        self.devices.settle();
    }

    fn form_key(&mut self, key: FormKey, out: &mut Vec<Command>) {
        let known = self.devices.len();
        let style = self.style;
        let Overlay::WhoIs(form) = &mut self.overlay else {
            return;
        };
        if let FormOutcome::Send(spec) = form.key(key, style, known) {
            self.overlay = Overlay::None;
            self.start_who_is(spec, out);
        }
    }

    fn start_who_is(&mut self, spec: WhoIsSpec, out: &mut Vec<Command>) {
        if let Some(op) = self.op.as_mut().filter(|op| op.running()) {
            // The worker ends the old listen window when the new one starts.
            op.state = OpState::Cancelled;
        }
        self.next_op += 1;
        self.last_spec = Some(spec.clone());
        self.op = Some(Operation {
            id: self.next_op,
            spec: spec.clone(),
            replies: 0,
            state: OpState::Sending,
        });
        out.push(Command::WhoIs {
            op: self.next_op,
            spec,
        });
    }

    fn picker_key(&mut self, key: PickerKey, out: &mut Vec<Command>) {
        let Overlay::Picker(picker) = &mut self.overlay else {
            return;
        };
        if let Some(iface) = picker.key(key) {
            self.overlay = Overlay::None;
            self.link = Link::Connecting;
            self.flash(
                format!(
                    "Using {} ({}, broadcast {}).",
                    iface.name, iface.ip, iface.broadcast
                ),
                FLASH_FOR,
            );
            out.push(Command::Connect {
                interface: iface.ip,
                broadcast: iface.broadcast,
            });
        }
    }

    fn worker_event(&mut self, event: WorkerEvent) {
        match event {
            WorkerEvent::Connected { local } => self.link = Link::Up { local },
            WorkerEvent::ConnectFailed { error } => {
                self.link = Link::Failed(error.clone());
                self.fail(error, 1);
            }
            WorkerEvent::Discovered(row) | WorkerEvent::Updated(row) => {
                if let Some(op) = self.op.as_mut().filter(|op| op.running()) {
                    op.replies += usize::from(op.spec.wants(row.instance));
                }
                self.devices.upsert(row);
            }
            WorkerEvent::Lost(row) => self.devices.remove(row.instance),
            WorkerEvent::Collision { retained, incoming } => {
                self.duplicates.record(&retained, &incoming);
            }
            WorkerEvent::Snapshot(rows) => self.devices.replace_all(rows),
            WorkerEvent::WhoIsSent { op } => {
                let now = self.now;
                if let Some(op) = self.running_op_mut(op) {
                    op.state = OpState::Listening {
                        until: now + op.spec.listen,
                    };
                }
            }
            WorkerEvent::OpFinished { op, outcome } => {
                if let Some(op) = self.running_op_mut(op) {
                    op.state = match outcome {
                        OpOutcome::Completed => OpState::Done,
                        OpOutcome::Cancelled => OpState::Cancelled,
                        OpOutcome::Failed(error) => OpState::Failed(error),
                    };
                }
            }
        }
    }
}

/// Apply one action. Returns the commands for the worker; quitting is
/// [`App::quit`].
pub(crate) fn update(app: &mut App, action: Action) -> Vec<Command> {
    let mut out = Vec::new();
    if !matches!(action, Action::Tick { .. }) {
        app.dirty = true;
    }
    match action {
        Action::Tick {
            now,
            dropped,
            log_generation,
        } => app.tick(now, dropped, log_generation),
        Action::Resize => {}
        Action::Quit => app.quit = true,
        Action::CtrlC => app.ctrl_c(&mut out),
        Action::Escape => app.escape(),
        Action::ToggleHelp => {
            app.overlay = match std::mem::replace(&mut app.overlay, Overlay::None) {
                Overlay::None => Overlay::Help,
                Overlay::Help => Overlay::None,
                other => other,
            }
        }
        Action::ToggleLog => app.show_log = !app.show_log,
        Action::OpenWhoIs => app.open_who_is(),
        Action::Move(movement) => app.devices.move_selection(movement),
        Action::CycleSort => {
            app.devices.cycle_sort();
            app.devices.settle();
        }
        Action::ReverseSort => {
            app.devices.reverse();
            app.devices.settle();
        }
        Action::StartFilter => app.filter_editing = true,
        Action::Filter(key) => app.filter_key(key),
        Action::Form(key) => app.form_key(key, &mut out),
        Action::Picker(key) => app.picker_key(key, &mut out),
        Action::Worker(event) => app.worker_event(event),
    }
    out
}
