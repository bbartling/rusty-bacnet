---
section: Changed
---
- **Python ScHub compatibility change:** `ca_cert` must explicitly name a usable
  trusted issuer CA PEM file. Omission, `None`, and empty paths now raise
  `ValueError` at construction; invalid files or mismatched server cert/key fail
  in `start()` before bind. The fifth positional parameter is unchanged, but its
  default no longer enables one-way TLS. Client verification and TLS 1.3 are
  mandatory, with no insecure escape hatch. The Python SC benchmark now supplies
  its generated CA. Rust hub `TlsAcceptor` injection was unchanged by that Python
  migration and is now retired above;
  #513 remains partial. See
  [ScHub](docs/python-api.md#schub).
