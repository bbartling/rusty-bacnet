---
section: Fixed
---
- **Breaking Notification Class Recipient_List cap (wire and Rust API):** the
  list now holds at most 32 destinations (#1098). Before, it grew without a
  bound until the framed decoder's 10,000-item limit, past which a write
  failed with INVALID_DATA_TYPE, so one event transition could fan out to
  thousands of notifications. An AddListElement that would leave more than 32 fails with
  RESOURCES / NO_SPACE_TO_ADD_LIST_ELEMENT, and its ChangeList-Error names the
  first request element that doesn't fit; a destination the list already holds
  still adds nothing and succeeds. A WriteProperty or WritePropertyMultiple of
  a longer list fails with RESOURCES / NO_SPACE_TO_WRITE_PROPERTY. Either way
  the list is unchanged. 32 is four times the AE-CRL-B minimum of 8 (Annex
  K.2.25), and a full list of device destinations, or of address destinations
  with MACs up to 6 octets, reads in one unsegmented 1476-octet APDU. In Rust,
  `MAX_RECIPIENT_LIST_DESTINATIONS` names the cap,
  `NotificationClass::add_destination` returns `Result` and refuses past it,
  and the `recipient_list` field is private: read it with `recipient_list()`.
