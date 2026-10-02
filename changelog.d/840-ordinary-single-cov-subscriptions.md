---
section: Fixed
---
- Ordinary and Single COV subscriptions now match the original BACnet recipient
  across routers (#840). Accepted renewals select the current delivery route;
  cancellation matches either router, obsolete-route cleanup preserves migrated
  entries, and existing renewal generations fence stale notification work.
  `CovRecipient` replaces `MultipleRecipient` and `CovPeerKey` without aliases,
  unifying subscription and quota/notification identity. Object/Property keys use
  `recipient`; `CovSubscription::recipient()` and `CovPolicy::reserved_recipients`
  replace `peer_key()` and `reserved_peer_keys`. Table admission rejects an empty
  routed source MAC before mutation. Valid quota and lifetime policies are unchanged.
