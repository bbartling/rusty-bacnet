---
section: Changed
---
- **SC empty Encapsulated-NPDU admission (Refs #519):** node receive and registered
  hub forwarding now discard zero-byte payloads before activity refresh. Eligible
  unicast returns `COMMUNICATION/PAYLOAD_EXPECTED` (7/149), marker zero and the
  request ID; broadcasts remain silent. Existing source/MU precedence, routing
  silence and pre-registration hub behavior remain. One-byte payloads and generic
  codec/raw-send syntax are unchanged; no NPCI/APDU validation is added. The new
  node NAK is the fourth path using the existing remaining-activity budget and
  fresh-only recovery; the hub retains its existing retirement supervisor, not a
  new NAK deadline. [Scoped wire, liveness and installed-native evidence](docs/conformance/standard-135-2020-ledger.md#empty-encapsulated-npdu-admission)
  does not promote support or claim full Annex AB conformance. #519 stays open/partial.
