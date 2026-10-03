---
section: Changed
---
- **Standalone/Docker SC compatibility change:** `bacnet-sc-hub` requires
  caller-provided `--ca`, `--cert`, `--key`; `bacnet-device --transport=sc`
  requires `--sc-ca`, `--sc-cert`, `--sc-key`, `--sc-hub`, `--sc-vmac` and
  `--sc-device-uuid`. The paired topology uses mutual TLS 1.3: the hub requires
  and verifies client certificates; the device validates the hub against its
  explicit CA and URL name and configures a matching operational certificate/key
  to offer for client authentication. These device settings do not attest what
  an arbitrary remote hub verifies. Both validate local credentials before
  networking. `--self-signed`/`--sc-no-verify` are rejected, not unsafe
  modes. Compose mounts only each endpoint's own credentials as read-only files.
  Provisioning is manual; see [development recipe and rotation](examples/docker/README.md).
  That standalone change left raw Rust hub APIs and comparison modes untouched;
  their subsequent retirement is described above. Non-SC behavior remains unchanged;
  no full-profile or performance qualification (#513 partial).
