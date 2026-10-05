---
section: Migration notes
---
- **Mutation authorizer (Rust API, #1319):** `MutationAuthorizationContext`'s
  `invoke_id` is an `Option<u8>` and its `service_choice` a `MutationService`
  (`Confirmed(choice)` or `Unconfirmed(choice)`); compare with
  `ConfirmedServiceChoice::X.into()`. Matches on `MutationTarget` need a
  `WriteGroup(WriteGroupTarget)` arm, and `MutationDecisionCounters` has a
  `write_group` row.
