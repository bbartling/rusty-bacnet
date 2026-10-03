---
section: Fixed
---
- **Breaking Calendar and Schedule wire format (and Rust API):** Calendar's
  Date_List now carries each BACnetCalendarEntry under its Clause 21 CHOICE
  tag: date `[0]`, date-range `[1]` (a frame around two application Dates) or
  weekNDay `[2]` (#996). Before, a date went out as an application Date and a
  date range or week-n-day as an application Octet String, so a peer decoding
  the specified tags misread or rejected every entry. Date_List is now
  network-writable and takes every choice, as Clause 12.9 asks of a writable
  Date_List: WriteProperty and WritePropertyMultiple replace the list (an empty
  payload clears it), and AddListElement and RemoveListElement edit it. A
  written value that isn't calendar entries, the old application-tagged forms
  included, is refused with INVALID_DATA_TYPE, an entry tag whose content
  doesn't decode with INVALID_DATA_ENCODING, and more than 1,024 entries with
  NO_SPACE_TO_WRITE_PROPERTY (NO_SPACE_TO_ADD_LIST_ELEMENT for
  AddListElement). The list services decode their elements with a calendar
  entry codec, so RemoveListElement matches entries by value, and either
  service refuses an element that isn't a well-formed entry with
  INVALID_DATA_TYPE, as for the other list codecs. Each entry is its own list element, so ReadRange addresses
  entries by position, and `CalendarObject::date_list()` reads them back for
  the application that evaluates Present_Value. Schedule changes the same way
  where it carries calendar entries and date ranges. Exception_Schedule encodes
  each BACnetSpecialEvent whole: its period (the inline calendar entry in a
  `[0]` frame, or the Calendar reference `[1]`, which it used to drop), the
  `[2]` time-value frame and event-priority `[3]`, which was an application
  Unsigned. Weekly_Schedule encodes each day as a BACnetDailySchedule, a `[0]`
  frame of time-values, instead of a list of Time and Octet String pairs.
  Effective_Period is two application Dates instead of an Octet String, and
  until set reads as the range with both dates unspecified, which covers every
  date, instead of NULL. The codecs move from `bacnet_services::schedule`,
  which is removed, to `bacnet_encoding::constructed`, so objects and services
  share one copy; it adds `encode_calendar_entry_list`,
  `decode_calendar_entry_list`, `encode_date_range`, `decode_date_range`,
  `encode_daily_schedule` and `decode_daily_schedule`. `BACnetDateRange::encode`
  and `BACnetDateRange::decode`, a bare eight-octet form with no wire meaning,
  are removed.
