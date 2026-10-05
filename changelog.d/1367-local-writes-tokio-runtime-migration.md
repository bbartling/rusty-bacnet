---
section: Migration notes
---
- **Local writes (Rust API, #1367):** await `write_local`, `write_local_encoded` and the `*_local`
  setters inside a Tokio runtime. Polled by another executor, they now fail with `Error::Encoding`
  before anything is written.
