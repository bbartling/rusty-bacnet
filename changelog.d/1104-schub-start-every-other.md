---
section: Fixed
commit: 6a8c79a18934f40e828a40902e58eb3beaa1e810
---
- **Breaking (Rust API):** every SC hub start method returns
  `Error::Transport` with the OS's `io::Error` when its bind fails, instead of
  `Error::Encoding` with the error's text (#1104).
