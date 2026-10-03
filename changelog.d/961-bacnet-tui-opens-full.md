---
section: Added
---
- `bacnet tui` opens a full-screen terminal UI (ratatui 0.30, crossterm 0.29)
  on the transport the global flags choose: BACnet/IP, BACnet/IPv6 or
  BACnet/SC. Its first screen is a live device table fed by the client's I-Am
  notifications, with a Who-Is form (local, global, directed or remote network,
  optional instance range), sort, a `/` filter, and a banner when two addresses
  claim one instance. A global or unbounded Who-Is asks for a second Enter
  after a one-line warning. It is read-only, and the status bar says so. On
  BACnet/IP without `-i` the interface picker is a dialog. Tracing goes to an
  in-app log pane (`L`) and optionally `--log-file`, never to the terminal
  while it is in raw mode; `--fps` sets the redraw rate, and an idle screen is
  not redrawn. Ctrl-C cancels the running Who-Is and a second press quits. The
  terminal is restored on panic (including a panic in a background task, after
  which the TUI stops drawing and exits 1), on SIGTERM, SIGHUP and SIGINT, and
  on Windows console close; a signal exit uses the shell's 128-plus-signal
  status on Unix. Without a terminal on stdin and stdout, with `TERM=dumb`, or
  when the terminal refuses raw mode, it exits 1 with a hint on stderr and an
  empty stdout. Below 80x24 it shows a notice instead of a broken layout.
  The UI loop runs in the CLI's boxed
  `block_on` future; a worker generic over the transport owns the client and
  reaches the UI over bounded channels, dropping and counting events (shown as
  `drop N`) instead of queueing without limit. The new default-on `tui` cargo
  feature can be turned off; `bacnet tui` then prints rebuild advice. The
  one-shot commands, the shell and their output are unchanged. The design is
  in `docs/design/tui.md` (#961, part of #975).
