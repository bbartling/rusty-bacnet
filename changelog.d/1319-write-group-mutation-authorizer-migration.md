---
section: Migration notes
---
- **Mutation authorizer (Rust API, #1319):** The context's `invoke_id` is an
  `Option<u8>` and `service_choice` a `MutationService`; compare with
  `ConfirmedServiceChoice::X.into()`. An authorizer whose `matches!`, `if let`
  or `_ => true` arm allows what it doesn't name now allows WriteGroup Channel
  writes it used to drop: handle `MutationTarget::WriteGroup` explicitly.
  `MutationDecisionCounters` gains `write_group`.
