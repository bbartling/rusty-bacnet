---
section: Migration notes
---
- DCC password configuration alone no longer enables the service. Explicitly
  select `RequirePassword` / `"require_password"` with a nonempty password, or
  the **INSECURE** `LegacyPermissive` / `"legacy_permissive"` compatibility mode.
  Exhaustive Rust `ServerConfig` literals need the new `dcc_policy` field.
  See [DCC policy](docs/dcc-policy.md) for precedence and unchanged timer limits.
