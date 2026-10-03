---
section: Changed
---
- `tokio-tungstenite` is built without TLS features. BACnet/SC already ran its
  own `tokio-rustls` handshake against the configured trust anchors and only
  wrapped the result for tungstenite, so nothing loads the operating system's
  root certificates any more. The benchmark tests dial the same way, so
  `rustls-native-certs` and its platform crates (`security-framework` on macOS,
  `schannel` on Windows, `openssl-probe` on Linux) leave `Cargo.lock`, and with
  it what cargo-deny and cargo-audit check. On macOS the CLI no longer links
  the Security and CoreFoundation frameworks. An application that relied on
  `bacnet-transport` to turn on a tungstenite TLS feature must now turn it on
  itself (#944).
