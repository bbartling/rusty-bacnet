---
section: Fixed
---
- Starting a server, a client or a BACnet/SC connection, and running the
  `bacnet` CLI, take much less stack in a debug build (#953). The native
  Windows tests (#950) found debug-build futures close to the 1 MiB that
  Windows gives a main thread and the 2 MiB a test thread gets. Server startup
  (every builder's `build()` and `BACnetServer::start*`), the TLS WebSocket
  dial (`TlsWebSocket::connect` and `connect_direct`), and the per-connection
  handshakes of the SC hub and the direct-connection listener now create
  their large inner futures on the heap, and the long-lived tasks a server
  starts (dispatch, timers, the network-number worker) are spawned boxed, so
  the public futures stay small without callers boxing them. The invoke-ID
  coordinator that every server, client and endpoint creates keeps its two
  256-entry tables on the heap: built inline, they took about 110 KB of stack
  in a debug build. On macOS, a debug build's `build()` needed 212 KiB of the
  calling thread's stack for a B/IP server and now needs 80 KiB; a B/IP
  client needed 148 and now 60, and a BACnet/SC server 330 and now 197, about
  145 KiB of which is tokio-tungstenite's handshake. The SC DCC mTLS server
  tests and the SC reconnect benchmark tests, whose fixtures now box their
  steps too, needed about 1 to 1.2 MiB of test-thread stack and now need
  about 0.25 MiB. On Linux x86_64, 13 tests overflowed a 1 MiB test-thread
  stack and 38 a 768 KiB one; none does now. The CLI now parses its command
  line on a thread with an 8 MiB stack: clap's derived parser alone took
  about 860 KiB of a debug build's main thread, and a `read` now needs about
  240 KiB of it. Startup makes a few more allocations, no per-request or
  per-packet path makes any (the `bip_latency` benchmark is unchanged), and
  no public signature changed. The native macOS and Windows jobs rerun the
  server, client, endpoint, integration, CLI and BACnet/SC transport tests
  with 1 MiB thread stacks, and on macOS give the CLI's processes a 1 MiB
  main thread, so a regression fails on both of those OSes rather than only
  on Windows.
