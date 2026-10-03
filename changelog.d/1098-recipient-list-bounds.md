---
section: Fixed
---
- **Breaking Recipient_List bounds (wire and Rust API):** follow-ups to the
  #1098 cap.
  - A configured recipient's address MAC is at most 18 octets (#1124),
    `BACnetAddress::MAX_MAC_LEN`. That is B/IPv6's form here, a 16-octet IPv6
    address and a 2-octet port, and the longest any data link this stack
    serves uses; the longest in the standard's network-layer address table is
    7. Before, any length was taken, so one destination could make every
    event transition re-encode and re-decode a list of any size; now a
    destination is at most 47 octets and a full list at most 1,504. A
    Recipient_List destination with a longer MAC doesn't decode: WriteProperty
    and WritePropertyMultiple fail with PROPERTY / INVALID_DATA_TYPE, and
    AddListElement with a ChangeList-Error naming the element. A write of
    Audit_Notification_Recipient fails with PROPERTY / INVALID_DATA_ENCODING.
    The stored value is unchanged. `NotificationClass::add_destination` and
    `DeviceObject::provision_audit_recipient` refuse one with the same codes.
    The new `decode_configured_recipient` applies the bound, and
    `decode_destination` uses it; `decode_recipient` still takes any length,
    since COV subscription lists and audit records report source addresses
    learned off the network.
  - Routing holds every Notification Class to the 32-destination cap, not
    only the built-in object (#1124). A custom NOTIFICATION_CLASS object
    serving a longer list gets nothing for the transition: none of its
    destinations, never some of them. The server logs a warning naming the
    class, and stops decoding at the first destination past the cap. Rust:
    `RecipientLookupOutcome` gains `RecipientListTooLong`;
    `get_notification_recipients_strict` returns `None` for it, and
    `get_notification_recipients` and `filter_recipient_list` an empty list.
    No counter covers event delivery, so none counts it.
  - The flat Recipient_List form from before #152 is gone (#1125). A local
    `write_property` or `write_local` of Recipient_List takes only the framed
    BACnetLIST of BACnetDestination in `PropertyValue::ApplicationData`; a
    `PropertyValue::List`, an empty one included, fails with PROPERTY /
    INVALID_DATA_TYPE. Routing and `filter_recipient_list` treat a custom
    class serving the flat form as an invalid list. Network writes were
    always framed, and neither the Python bindings nor the CLI built the flat
    form. To clear the list locally, write `PropertyValue::ApplicationData`
    of no bytes (Python: `PropertyValue.application_data(b"")`).
