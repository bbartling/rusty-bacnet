---
section: Changed
---
- **SC Address-Resolution accepting capability (Refs #733):** nodes without a
  live matching direct listener now return `7/45` rather than an empty/configured
  URI ACK. A live listener can still ACK an empty URI list. Capability denial
  preserves the existing bounded NAK and heartbeat policy. Python known-function
  vectors now expect each family's actual response and retain strict ordering
  checks. See [scoped evidence](docs/conformance/standard-135-2020-ledger.md#node-address-resolution-accepting-capability).
