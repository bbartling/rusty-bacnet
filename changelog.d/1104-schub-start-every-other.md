---
section: Fixed
---
- **Breaking (Rust API):** every SC hub start method returns
  `Error::Transport` with the OS's `io::Error` when its bind fails, instead of
  `Error::Encoding` with the error's text (#1104).
