---
section: Changed
---
- **Scoped SC Device UUID acceptance closeout (#517):** document the owner-approved
  [six-criterion resolution and evidence](docs/conformance/standard-135-2020-ledger.md#device-identity-acceptance-closeout)
  for startup/default/nil identity and peer admission. Runtime is unchanged;
  existing proof is reused. Caller provisioning/durable lifetime storage remain
  required; nonzero bits remain opaque, with raw/manual and post-start mutable
  paths excluded. No RFC bit-profile, enforced lifetime or full Annex AB claim.
  Issue closure belongs to this proposed closeout; earlier entries retain their
  slice-time behavior and exclusions.
