---
section: Fixed
---
- The VT, WriteGroup, Who-Am-I and You-Are codecs now put the same bytes on
  the wire as the Clause 21 grammar, so peers that follow the standard can
  decode them (#912). Each encoding is checked against byte vectors worked out
  by hand from the Clause 20 rules. The public API changes with the wire format:
  - `VTOpenRequest` gains the mandatory `local_vt_session_identifier`, and
    `vt_class` is now a `VTClass`.
  - The VT-Data flag is sent as an Unsigned, not a Boolean.
  - `VTDataAck` becomes an enum, `AllAccepted` or `Partial { accepted_octet_count }`.
  - `VTCloseRequest::encode` returns `Result` and rejects an empty list.
  - WriteGroup channels are `u16` channel numbers, not object identifiers.
  - A WriteGroup value is one untagged BACnetChannelValue, without the old
    `[2]` wrapper.
  - `group_number` is a `NonZeroU32`, and `WriteGroupRequest::encode` returns
    `Result`. It checks both priorities (1–16) and rejects an empty change list.
  - `WhoAmIRequest` now carries the mandatory vendor ID, model name and serial
    number.
  - You-Are fields use application tags. Encode and decode require a Device
    identifier, a MAC address, or both, and a device identifier must be a
    Device object.
  - Each WriteGroup value must be exactly one well-formed BACnetChannelValue:
    a primitive of any character set, or a lighting command whose fields are in
    order and have valid lengths.
  - Every decoder rejects trailing data.
  - Python: `vt_open` takes a `VTClass` and a local session ID; `vt_data`
    always returns `all_new_data_accepted`; `write_group` takes integer
    channels; `who_am_i` takes the three identity arguments.
  - `docs/rust-api.md` no longer calls client methods that don't exist. The
    VT, Who-Am-I, WriteGroup, GetAlarmSummary, GetEnrollmentSummary,
    LifeSafetyOperation, PrivateTransfer and TextMessage examples now build
    the `bacnet_services` request and send it with `confirmed_request` or
    `unconfirmed_request`.
