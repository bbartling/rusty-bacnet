---
section: Changed
---
- **Bounded endpoint source ReadProperty audit reporting (Refs #727, #345):**
  Direct B/IP IPv4 `ClientOnly`/`Both` sessions can send source READ records to
  their Device-owned recipient in either notification mode. Actual invoke IDs,
  request-time timestamps and terminal outcomes survive caller cancellation and
  retries; ACK object/property/index must match before success is recorded.
  Source emission requires absent Monitored_Objects. Separate 64-operation and
  64-notification limits, an absolute three-second notification deadline and
  joined session shutdown bound retained work. Queue expiry prevents canceled
  notifications from being transmitted later; already-started sends remain
  ambiguous. Delivery failure updates Reporter health without changing the READ
  result. The Device recipient extension is described above; full Audit Reporting
  conformance remains out of scope. Source loss summaries are described above. See
  [endpoint source READ](docs/rust-api.md#bounded-endpoint-source-read-reporting).
  **Pre-1.0 internal Rust API cleanup:** shared coordinator
  `LeaseOwner::ServerNotification` / `LeaseMetadata::server_notification` become
  `Notification` / `notification`, reflecting ClientOnly notification ownership.
