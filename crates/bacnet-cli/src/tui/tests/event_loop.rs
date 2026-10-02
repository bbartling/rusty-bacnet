//! The UI loop on a `TestBackend`, with scripted terminal input and paused
//! time: quitting, Ctrl-C, release events, and redrawing only when dirty.

use std::io;
use std::sync::atomic::AtomicU64;
use std::sync::Arc;
use std::time::Duration;

use futures_util::stream::{self, Stream};
use ratatui::crossterm::event::{Event, KeyCode, KeyEvent, KeyEventKind, KeyModifiers};
use tokio::sync::mpsc;

use super::*;
use crate::tui::event_loop::{run, LoopIo, LoopStats};
use crate::tui::terminal::Signals;

type Input = std::pin::Pin<Box<dyn Stream<Item = io::Result<Event>>>>;

struct Harness {
    keys: mpsc::UnboundedSender<Event>,
    events: mpsc::Sender<WorkerEvent>,
    commands: mpsc::Receiver<Command>,
    io: LoopIo<Input>,
}

fn harness() -> Harness {
    let (keys, key_rx) = mpsc::unbounded_channel();
    let input: Input = Box::pin(stream::unfold(key_rx, |mut rx| async move {
        rx.recv().await.map(|event| (Ok(event), rx))
    }));
    let (events, event_rx) = mpsc::channel(64);
    let (command_tx, commands) = mpsc::channel(16);
    Harness {
        keys,
        events,
        commands,
        io: LoopIo {
            input,
            events: event_rx,
            commands: command_tx,
            dropped: Arc::new(AtomicU64::new(0)),
            fps: 20,
            signals: Signals::none(),
        },
    }
}

fn key(code: KeyCode, modifiers: KeyModifiers, kind: KeyEventKind) -> Event {
    let mut event = KeyEvent::new(code, modifiers);
    event.kind = kind;
    Event::Key(event)
}

fn press_event(code: KeyCode) -> Event {
    key(code, KeyModifiers::NONE, KeyEventKind::Press)
}

async fn run_app(app: &mut App, io: &mut LoopIo<Input>) -> LoopStats {
    let mut terminal = Terminal::new(TestBackend::new(80, 24)).unwrap();
    tokio::time::timeout(Duration::from_secs(60), run(&mut terminal, app, io))
        .await
        .expect("loop did not finish")
        .unwrap()
}

#[tokio::test(start_paused = true)]
async fn an_idle_screen_is_drawn_once_and_q_quits() {
    let mut h = harness();
    let keys = h.keys.clone();
    tokio::spawn(async move {
        // Ten seconds of 20 fps ticks with nothing changing.
        tokio::time::sleep(Duration::from_secs(10)).await;
        keys.send(press_event(KeyCode::Char('q'))).unwrap();
    });
    let mut app = new_app(None);
    let stats = run_app(&mut app, &mut h.io).await;
    assert!(app.quit);
    assert_eq!(stats.frames, 1, "no redraw without a change");
}

#[tokio::test(start_paused = true)]
async fn a_burst_of_worker_events_costs_one_frame() {
    let mut h = harness();
    let keys = h.keys.clone();
    let events = h.events.clone();
    tokio::spawn(async move {
        events
            .send(WorkerEvent::Connected {
                local: "10.0.0.1:47808".into(),
            })
            .await
            .unwrap();
        for i in 0..50 {
            let address = format!("10.0.0.{i}:47808");
            events
                .send(WorkerEvent::Discovered(row(i, &address, 1, 0)))
                .await
                .unwrap();
        }
        // Less than a second: the ages do not change, so no more redraws.
        tokio::time::sleep(Duration::from_millis(500)).await;
        keys.send(press_event(KeyCode::Char('q'))).unwrap();
    });
    let mut app = new_app(None);
    let stats = run_app(&mut app, &mut h.io).await;
    assert_eq!(app.devices.len(), 50);
    assert!(
        (2..=3).contains(&stats.frames),
        "initial frame plus one or two for the burst, got {}",
        stats.frames
    );
}

#[tokio::test(start_paused = true)]
async fn only_presses_count_and_ctrl_c_twice_quits() {
    let mut h = harness();
    // A release of `q` (Windows sends them) must not quit.
    h.keys
        .send(key(
            KeyCode::Char('q'),
            KeyModifiers::NONE,
            KeyEventKind::Release,
        ))
        .unwrap();
    let ctrl_c = key(
        KeyCode::Char('c'),
        KeyModifiers::CONTROL,
        KeyEventKind::Press,
    );
    h.keys.send(ctrl_c.clone()).unwrap();
    h.keys.send(ctrl_c).unwrap();
    let mut app = connected_app();
    run_app(&mut app, &mut h.io).await;
    assert!(app.quit);
    assert_eq!(app.exit_error, None);
}

#[tokio::test(start_paused = true)]
async fn commands_from_keys_reach_the_worker() {
    let mut h = harness();
    for event in [
        press_event(KeyCode::Char('d')),
        press_event(KeyCode::Tab),
        press_event(KeyCode::Char('7')),
        press_event(KeyCode::Enter),
        press_event(KeyCode::Char('q')),
    ] {
        h.keys.send(event).unwrap();
    }
    let mut app = connected_app();
    run_app(&mut app, &mut h.io).await;
    let Ok(Command::WhoIs { spec, .. }) = h.commands.try_recv() else {
        panic!("no WhoIs command");
    };
    assert_eq!(spec.range, Some((7, 7)));
}

#[tokio::test(start_paused = true)]
async fn the_loop_ends_when_input_ends_and_survives_a_stopped_worker() {
    let mut h = harness();
    // A worker that has already gone: the loop keeps running.
    let (_, closed) = mpsc::channel(1);
    h.io.events = closed;
    let keys = h.keys;
    tokio::spawn(async move {
        tokio::time::sleep(Duration::from_secs(1)).await;
        drop(keys);
    });
    let mut app = connected_app();
    run_app(&mut app, &mut h.io).await;
    assert!(app.quit, "end of input quits");
    assert_eq!(app.exit_error, None);
}
