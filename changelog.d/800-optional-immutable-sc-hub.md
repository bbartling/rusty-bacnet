---
section: Added
---
- Optional immutable SC Hub certificate bindings restrict verified leaf SHA-256
  identities to provisioned UUID/VMAC groups, including offline reservations and
  listed rotation certificates. Rust and frozen Python group values share validation;
  existing admission policy remains conjunctive. No-map CA-valid admission remains
  an intentional profile; no downstream leaf-authentication claim is made (#800).
