---
section: Changed
---
- **SC hub conflict-aware admission (Refs #767, #476):** Rust admission input now
  includes a fixed classification of the current UUID/VMAC registration under
  the same lock as the decision. Python supports the static
  `admission_policy="deny_uuid_replacement"` mode through that authority, without
  Python callbacks. Opt-in refusal preserves an incumbent; default known-UUID
  replacement and different-UUID VMAC collision handling remain unchanged.
  Refusal is local security policy before protocol acceptance, not certificate
  identity proof or a broader Annex AB conformance claim.
