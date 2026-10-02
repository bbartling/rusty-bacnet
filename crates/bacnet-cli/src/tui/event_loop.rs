//! The UI loop: one `select!` over terminal input, a frame interval, the
//! worker's events and signals. It runs on the thread that `block_on`s the
//! CLI's boxed future, not in `tokio::spawn`, so a slow `terminal.draw` never
//! holds up a worker task.
//!
//! Only key presses count (Windows also reports releases). Redraws happen
//! when the state is dirty: straight after a key, so typing feels immediate,
//! and otherwise at most once per frame, so a burst of worker events costs one
//! draw per frame however many events it holds.

use std::io;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;

use futures_util::{Stream, StreamExt};
use ratatui::backend::Backend;
use ratatui::crossterm::event::{Event, KeyEventKind};
use ratatui::Terminal;
use tokio::sync::mpsc;
use tokio::time::MissedTickBehavior;

use super::app::{update, Action, App};
use super::keymap::map_key;
use super::message::{Command, WorkerEvent};
use super::terminal::Signals;
use super::view;

/// Worker events applied per wake-up before yielding to input and frames.
const DRAIN_BUDGET: usize = 256;

/// Channels and settings the loop runs with.
pub(crate) struct LoopIo<I> {
    /// Terminal events.
    pub(crate) input: I,
    /// Events from the worker.
    pub(crate) events: mpsc::Receiver<WorkerEvent>,
    /// Commands to the worker.
    pub(crate) commands: mpsc::Sender<Command>,
    /// The worker's dropped-events counter.
    pub(crate) dropped: Arc<AtomicU64>,
    /// Frames per second.
    pub(crate) fps: u16,
    /// Signals that end the loop.
    pub(crate) signals: Signals,
}

/// Counters for tests.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub(crate) struct LoopStats {
    /// Frames drawn.
    pub(crate) frames: u64,
}

/// Run until the app quits, input ends, or a signal arrives.
pub(crate) async fn run<B, I>(
    terminal: &mut Terminal<B>,
    app: &mut App,
    io: &mut LoopIo<I>,
) -> Result<LoopStats, Box<dyn std::error::Error>>
where
    B: Backend,
    B::Error: Send + Sync + 'static,
    I: Stream<Item = io::Result<Event>> + Unpin,
{
    let mut stats = LoopStats::default();
    let period = Duration::from_secs(1) / u32::from(io.fps.max(1));
    let mut frames = tokio::time::interval(period);
    frames.set_missed_tick_behavior(MissedTickBehavior::Skip);
    let mut worker_open = true;
    draw(terminal, app, &mut stats)?;
    while !app.quit {
        tokio::select! {
            input = io.input.next() => match input {
                Some(Ok(Event::Key(key))) if key.kind == KeyEventKind::Press => {
                    if let Some(action) = map_key(app, key) {
                        apply(app, action, &io.commands);
                    }
                    if app.dirty && !app.quit {
                        draw(terminal, app, &mut stats)?;
                    }
                }
                Some(Ok(Event::Resize(..))) => {
                    apply(app, Action::Resize, &io.commands);
                    draw(terminal, app, &mut stats)?;
                }
                Some(Ok(_)) => {}
                Some(Err(error)) => return Err(error.into()),
                None => app.quit = true,
            },
            _ = frames.tick() => {
                let tick = Action::Tick {
                    now: tokio::time::Instant::now().into_std(),
                    dropped: io.dropped.load(Ordering::Relaxed),
                    log_generation: app.log.generation(),
                };
                apply(app, tick, &io.commands);
                if app.dirty {
                    draw(terminal, app, &mut stats)?;
                }
            }
            event = io.events.recv(), if worker_open => match event {
                Some(event) => {
                    apply(app, Action::Worker(event), &io.commands);
                    for _ in 1..DRAIN_BUDGET {
                        match io.events.try_recv() {
                            Ok(event) => apply(app, Action::Worker(event), &io.commands),
                            Err(_) => break,
                        }
                    }
                }
                None => {
                    worker_open = false;
                    if app.exit_error.is_none() && !app.quit {
                        tracing::warn!("the network worker stopped");
                    }
                }
            },
            signal = io.signals.recv() => {
                app.exit_error = Some(format!("terminated by {signal}"));
                app.quit = true;
            }
        }
    }
    Ok(stats)
}

fn apply(app: &mut App, action: Action, commands: &mpsc::Sender<Command>) {
    for command in update(app, action) {
        if let Err(error) = commands.try_send(command) {
            tracing::warn!("worker command not sent: {error}");
        }
    }
}

fn draw<B>(
    terminal: &mut Terminal<B>,
    app: &mut App,
    stats: &mut LoopStats,
) -> Result<(), Box<dyn std::error::Error>>
where
    B: Backend,
    B::Error: Send + Sync + 'static,
{
    app.settle();
    terminal.draw(|frame| view::draw(frame, app))?;
    app.dirty = false;
    stats.frames += 1;
    Ok(())
}
