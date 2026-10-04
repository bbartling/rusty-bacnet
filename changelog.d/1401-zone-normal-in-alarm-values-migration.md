---
section: Migration notes
---
- **Access Zone (#1401):** drop NORMAL from Alarm_Values, whether set with
  `AccessZoneObject::set_alarm_values` or written by a client; the zone now
  refuses it with VALUE_OUT_OF_RANGE.
