---
section: Changed
---
- Notification Class recipients use typed bit strings. `BACnetDestination.valid_days`
  is a new `bacnet_types::bitstring::DaysOfWeek`, which keeps Monday in bit 0
  like the other `bitstring` types, and `BACnetDestination.transitions` is an
  `EventTransitionBits`; both were raw `u8` masks. The Recipient_List codec
  converts with `to_bacnet`/`from_bacnet`, so the wire bytes are unchanged and
  a nonzero pad bit from a peer is still dropped. `primitives::DaysOfWeek`, an
  unused right-aligned copy of the same bit string with Monday at `0x40`, is
  removed in favour of the new type. The recipient filters take the current day
  as a `DaysOfWeek`: `local_day_and_time` returns one,
  `ClockFrame::day_of_week` returns `Option<DaysOfWeek>`, and
  `lookup_notification_recipients`, `get_notification_recipients`,
  `get_notification_recipients_strict` and `filter_recipient_list` take
  `today: DaysOfWeek` instead of `today_bit: u8`. `NotificationClass.ack_required`
  is an `EventTransitionBits` instead of `[bool; 3]`, and Ack_Required reads
  return the same octet as before. `bitstring::pack_octet` and `unpack_octet`
  are no longer public; use the typed `to_bacnet`/`from_bacnet` methods (#930).
