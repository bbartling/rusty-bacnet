---
section: Changed
---
- **Endpoint source Device recipient (Refs #728, pre-1.0 API break):** removes
  `StaticSourceAuditRecipient`, `static_source_audit_recipient` and ownership-only
  source mode. Provision the built-in Device's typed recipient; configure route
  facts with `source_audit_device_binding`. Source selection requires that value
  even at NONE. Direct IPv4 B/IP `ClientOnly` supports trusted local changes through
  `EndpointSession::write_audit_recipient`;
  `Both` requires the existing Device write authorizer for inbound WP. Actual
  changes atomically admit old/new notifications; in-flight READs retain their
  captured destination. Endpoint WPM stays unsupported. Canceled session/ingress
  stop retains joins, and source overrides become inactive on sealing while
  membership remains protected through task quiescence. Post-ingress profile
  initialization errors run the same cancellation-safe cleanup and leave a terminal
  session; preflight failures remain retryable. See the
  [bounded contract](docs/device-audit-recipient.md).
