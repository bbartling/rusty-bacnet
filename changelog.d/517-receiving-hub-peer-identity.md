---
section: Changed
---
- **Receiving hub peer identity compatibility break (Refs #517):** all-zero
  Device UUIDs in received Connect-Request now fail after TLS/WebSocket setup,
  before activity refresh, registration, capacity decisions or replacement.
  Eligible replies use `COMMUNICATION/PARAMETER_OUT_OF_RANGE` (7/80), marker zero,
  with existing envelope addressing/suppression. New malformed peers close;
  malformed repeats preserve their existing registration and liveness state.
  This is local nonzero-identity policy, not UUID version/variant enforcement.
  Nonzero UUIDs remain opaque and intended same-UUID replacement remains.
  Generic codecs/manual raw sending still allow nil syntax. The Connect-Accept
  extension below supersedes this slice's original response-policy exclusion.
  No pre-dial peer check, certificate binding, persistence or full Annex AB claim;
  #517 remained open at slice time. Earlier startup-only entries describe those slices' scope.
