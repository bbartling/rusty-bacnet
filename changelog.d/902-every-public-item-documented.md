---
section: Changed
---
- Every public item is documented, and `missing_docs` is now `deny`
  (`bacnet-benchmarks`, which isn't published, opts out). CI treats clippy and
  rustdoc warnings as errors, and checks three ways: the workspace with every
  optional feature, the PyO3 crate, and each published crate on its own with
  default features (plus `no_std` `bacnet-types`). Per-crate features that
  nothing else enables, `bacnet-endpoint/sc-tls` and `bacnet-cli/{sc-tls,pcap}`,
  are now built and tested; before, CI enabled only transport features, and 58
  tests behind them never ran there. The CLI's two feature-off tests keep
  running in a default-feature step (#902, #906).
