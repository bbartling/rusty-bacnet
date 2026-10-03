---
section: Changed
---
- Optional dependencies are no longer published as features. Feature lists now
  enable them with `dep:`, so Cargo stops creating an implicit feature for each
  one, such as `bacnet-transport/rustls` or `bacnet-cli/tokio-rustls`, none of
  which was a supported configuration. What remains is the documented set:
  `bacnet-transport`'s `ipv6`, `sc-tls`, `serial`, `serial-gpio` and `ethernet`;
  `sc-tls` on `bacnet-client` (plus `ipv6`), `bacnet-server` and
  `bacnet-endpoint`; `sc-tls` and `pcap` on `bacnet-cli`; `std` and `serde` on
  `bacnet-types`. A build that named a removed feature enables the documented
  one instead: `sc-tls` for `futures-util`, `rustls`, `rustls-pki-types`,
  `tokio-rustls` and `tokio-tungstenite`, `serial` for `tokio-serial`, and
  `serial-gpio` for `gpiocdev`. The unpublished benchmark crate's
  `console-subscriber` is likewise reachable only through `console` (#917).
