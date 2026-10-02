---
section: Changed
---
- **Breaking `Error` variant, BBMD helper bounds and live-state accessors:**
  `bacnet_types::error::Error` gains
  `UnsupportedTransport { required: DataLink, actual: DataLink }`, so an
  exhaustive match on `Error` needs a new arm. Its message reads, for example,
  "operation requires BACnet/IP; this transport is MS/TP". The `BACnetClient`
  BBMD helpers (`read_bdt`, `write_bdt`, `read_fdt`, `delete_fdt_entry`,
  `register_foreign_device_bvlc`) move from `BACnetClient<BipTransport>` to any
  `BACnetClient<T>` whose transport implements `AsBip`. Calls on a B/IP client
  compile unchanged. On a client over `AnyTransport` they work for the `Bip`
  variant and return `Error::UnsupportedTransport` for any other, before
  sending anything. `ScTransport::connection()` and `MstpTransport::node_state()`
  are no longer public: they handed out the live SC connection, identity
  included, and the MS/TP master node whose lock the token loop takes. Read the
  SC link state with `connection_state_changes()` and MS/TP counts with
  `diagnostics()` (#956).
