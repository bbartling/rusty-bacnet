---
section: Changed
---
- `AnyTransport::Bip` now holds a `Box<BipTransport>`, like `Sc`: B/IP made the
  enum several times larger than its other variants. `From<BipTransport>` still
  converts; direct constructors become `AnyTransport::Bip(Box::new(..))`. The
  endpoint-core `ClassifierExit::PolicyRouteFull` and `PolicyRouteClosed` payloads
  are boxed for the same reason (#902).
