---
section: Added
---
- **Breaking (wire, Rust API):** a running server's application can feed an
  Averaging object samples with `add_averaging_sample_local`, and the object
  takes SubscribeCOVProperty. `AveragingObject::add_sample` returns `Result`
  (#1083).
