---
section: Changed
---
- **Python standalone mutation policy (Refs #768):** `BACnetServer` accepts the
  keyword-only `mutation_policy="permissive" | "deny_all"`, validated before
  startup and passed to the existing native gate. The native default remains
  permissive; deny-all covers the ten existing mutation services while reads
  and trusted local writes remain available. DCC, ReinitializeDevice, LifeSafety,
  Audit and endpoint authorization stay separate. No Python callback is added.
