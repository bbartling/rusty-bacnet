---
section: Changed
commit: dfc317a071f8abfa8a0182874cc65fd830a8e211
---
- `tokio-tungstenite` is built without TLS features, so nothing loads the
  system root certificates and the native-certs crates leave the lockfile
  (#944).
