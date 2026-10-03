---
section: Fixed
---
- **Breaking NPDU address-length bound (wire, Rust API):** the network layer
  refuses an NPDU whose DLEN or SLEN is past 18 octets,
  `NpduAddress::MAX_MAC_LEN` (#1141). The NPDU codec took any length up to
  255, though no standard data link uses more than 7 (Table 6-2) and the
  longest MAC this stack serves is 18 (B/IPv6). The bound sits in the codec,
  so the router, `NetworkLayer` and everything that decodes or encodes an NPDU
  share it without a per-transport check, and it equals
  `BACnetAddress::MAX_MAC_LEN` from #1124.
  - `decode_npdu` returns the new `NpduDecodeError`: an over-long DLEN or SLEN
    is `AddressTooLong { field, length, dnet }`, checked before the address
    octets are read, and any other malformation is `Malformed(Error)`. It
    converts into `Error` (the over-long case as `Error::OutOfRange`), so `?`
    keeps working.
  - `encode_npdu` refuses a DADR or SADR longer than 18 octets with
    `Error::Encoding`; the limit was 255.
  - `NetworkLayer` drops such an NPDU before admission and counts it in the
    new `address_length_drops()`. A non-router sends no reject.
  - `BACnetRouter` neither forwards nor delivers it and counts it in its own
    `address_length_drops()`. When the NPDU names a specific DNET, the router
    answers the sender with Reject-Message-To-Network reason 6
    (`ADDRESSING_ERROR`, Clause 6.4.4) for that DNET, shaped like its
    unknown-DNET reject. A global broadcast or an NPDU with no DNET is
    dropped without a reject.
