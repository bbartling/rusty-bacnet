//! Terminal ownership: the non-TTY guard, raw mode and the alternate screen,
//! the panic hook, and the signals that must restore the terminal.
//!
//! Setup mirrors `ratatui::init` and teardown calls `ratatui::try_restore`.
//! The panic hook is our own rather than the one `ratatui::init` installs so
//! that it shares one idempotent [`restore`] with normal exit and signal exit,
//! and so its ordering is testable: it restores the terminal first, then runs
//! the previous hook, which prints the panic message on a usable screen.

use std::ffi::OsStr;
use std::io::{self, IsTerminal};
use std::panic::PanicHookInfo;
use std::sync::atomic::{AtomicBool, Ordering};

use ratatui::backend::CrosstermBackend;
use ratatui::crossterm::cursor::Show;
use ratatui::crossterm::execute;
use ratatui::crossterm::terminal::{enable_raw_mode, EnterAlternateScreen};
use ratatui::{DefaultTerminal, Terminal};

/// True while raw mode and the alternate screen are on.
static ACTIVE: AtomicBool = AtomicBool::new(false);

/// Why the TUI cannot run with these streams, or `None` if it can.
pub(crate) fn unusable_terminal(
    stdin_tty: bool,
    stdout_tty: bool,
    term: Option<&OsStr>,
) -> Option<&'static str> {
    if !stdin_tty || !stdout_tty {
        Some("stdin and stdout must both be a terminal")
    } else if term.is_some_and(|t| t == "dumb") {
        Some("TERM is \"dumb\"")
    } else {
        None
    }
}

/// Check the real process streams; the error is the hint for stderr.
pub(crate) fn check_terminal() -> Result<(), String> {
    let term = std::env::var_os("TERM");
    match unusable_terminal(
        io::stdin().is_terminal(),
        io::stdout().is_terminal(),
        term.as_deref(),
    ) {
        Some(reason) => Err(format!(
            "Error: bacnet tui needs an interactive terminal ({reason}).\n\
             hint: for scripts and pipes use the one-shot commands, such as \
             `bacnet discover --json`."
        )),
        None => Ok(()),
    }
}

/// A boxed panic hook, as `std::panic::take_hook` returns it.
pub(crate) type PanicHook = Box<dyn Fn(&PanicHookInfo<'_>) + Sync + Send + 'static>;

/// A hook that runs `restore` and then `previous`.
pub(crate) fn chain_panic_hook(
    previous: PanicHook,
    restore: impl Fn() + Sync + Send + 'static,
) -> PanicHook {
    Box::new(move |info| {
        restore();
        previous(info);
    })
}

/// Enter raw mode and the alternate screen, after installing the panic hook.
pub(crate) fn enter() -> io::Result<DefaultTerminal> {
    let previous = std::panic::take_hook();
    std::panic::set_hook(chain_panic_hook(previous, restore));
    enable_raw_mode()?;
    ACTIVE.store(true, Ordering::SeqCst);
    let terminal = execute!(io::stdout(), EnterAlternateScreen)
        .and_then(|()| Terminal::new(CrosstermBackend::new(io::stdout())));
    if terminal.is_err() {
        restore();
    }
    terminal
}

/// Leave raw mode and the alternate screen and show the cursor. Does nothing
/// unless [`enter`] succeeded, so normal exit, a signal and the panic hook can
/// all call it.
pub(crate) fn restore() {
    if ACTIVE.swap(false, Ordering::SeqCst) {
        // Errors are ignored: after SIGHUP there is no terminal to restore.
        let _ = ratatui::try_restore();
        let _ = execute!(io::stdout(), Show);
    }
}

/// Signals that end the TUI. The loop restores the terminal before exiting.
///
/// In raw mode Ctrl-C arrives as a key, not SIGINT, so these come from
/// outside: `kill`, a closed SSH session, a closed console window.
pub(crate) struct Signals {
    #[cfg(unix)]
    unix: Option<[(tokio::signal::unix::Signal, &'static str); 3]>,
    #[cfg(windows)]
    windows: Option<(
        tokio::signal::windows::CtrlClose,
        tokio::signal::windows::CtrlBreak,
    )>,
}

impl Signals {
    /// Listen for SIGTERM, SIGHUP and SIGINT (Unix) or console close and
    /// Ctrl-Break (Windows).
    pub(crate) fn install() -> io::Result<Self> {
        #[cfg(unix)]
        {
            use tokio::signal::unix::{signal, SignalKind};
            Ok(Self {
                unix: Some([
                    (signal(SignalKind::terminate())?, "SIGTERM"),
                    (signal(SignalKind::hangup())?, "SIGHUP"),
                    (signal(SignalKind::interrupt())?, "SIGINT"),
                ]),
            })
        }
        #[cfg(windows)]
        {
            use tokio::signal::windows::{ctrl_break, ctrl_close};
            Ok(Self {
                windows: Some((ctrl_close()?, ctrl_break()?)),
            })
        }
        #[cfg(not(any(unix, windows)))]
        {
            Ok(Self {})
        }
    }

    /// No signals: [`recv`](Self::recv) never resolves. For tests.
    #[cfg(test)]
    pub(crate) fn none() -> Self {
        Self {
            #[cfg(unix)]
            unix: None,
            #[cfg(windows)]
            windows: None,
        }
    }

    /// The name of the next signal.
    pub(crate) async fn recv(&mut self) -> &'static str {
        #[cfg(unix)]
        if let Some([(a, a_name), (b, b_name), (c, c_name)]) = &mut self.unix {
            tokio::select! {
                Some(()) = a.recv() => return *a_name,
                Some(()) = b.recv() => return *b_name,
                Some(()) = c.recv() => return *c_name,
                else => {}
            }
        }
        #[cfg(windows)]
        if let Some((close, brk)) = &mut self.windows {
            tokio::select! {
                Some(()) = close.recv() => return "console close",
                Some(()) = brk.recv() => return "Ctrl-Break",
                else => {}
            }
        }
        std::future::pending().await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{Arc, Mutex};

    #[test]
    fn guard_needs_two_ttys_and_a_real_term() {
        assert_eq!(
            unusable_terminal(true, true, Some(OsStr::new("xterm"))),
            None
        );
        assert_eq!(
            unusable_terminal(true, true, None),
            None,
            "Windows has no TERM"
        );
        for (stdin, stdout) in [(false, true), (true, false), (false, false)] {
            assert!(unusable_terminal(stdin, stdout, None)
                .unwrap()
                .contains("must both be a terminal"));
        }
        assert!(unusable_terminal(true, true, Some(OsStr::new("dumb")))
            .unwrap()
            .contains("dumb"));
    }

    #[test]
    fn panic_hook_restores_before_the_previous_hook() {
        let order = Arc::new(Mutex::new(Vec::new()));
        let previous: PanicHook = {
            let order = Arc::clone(&order);
            Box::new(move |_| order.lock().unwrap().push("previous hook"))
        };
        let hook = {
            let order = Arc::clone(&order);
            chain_panic_hook(previous, move || order.lock().unwrap().push("restore"))
        };
        // A PanicHookInfo exists only inside a panic, so install the hook,
        // panic, and put the process's own hook back.
        let original = std::panic::take_hook();
        std::panic::set_hook(hook);
        let result = std::panic::catch_unwind(|| panic!("boom"));
        std::panic::set_hook(original);
        assert!(result.is_err());
        assert_eq!(*order.lock().unwrap(), ["restore", "previous hook"]);
    }

    #[test]
    fn restore_is_a_no_op_until_the_terminal_is_entered() {
        // Never entered in tests: restore must not touch stdout or panic.
        restore();
        restore();
        assert!(!ACTIVE.load(Ordering::SeqCst));
    }
}
