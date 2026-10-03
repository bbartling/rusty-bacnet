---
section: Fixed
---
- `bacnet` (the CLI) no longer overflows the main thread's stack on Windows
  (#950). `#[tokio::main]` polled its large command futures on the main
  thread, whose stack is 1 MiB on Windows, and a debug build aborted on its
  first BACnet/SC command. The command futures now live on the heap.
