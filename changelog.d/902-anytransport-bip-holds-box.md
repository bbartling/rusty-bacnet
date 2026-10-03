---
section: Changed
---
- **Breaking (Rust API):** `AnyTransport::Bip` holds a `Box<BipTransport>`,
  like `Sc`, and `From<BipTransport>` still converts (#902).
