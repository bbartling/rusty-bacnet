---
section: Added
commit: 417f7985b8ca6b785cc7ae5a17aa61a88136c03a
---
- **Breaking (wire, Rust API):** a running server's application can feed an
  Averaging object samples with `add_averaging_sample_local`, and the object
  takes SubscribeCOVProperty. `AveragingObject::add_sample` returns `Result`
  (#1083).
