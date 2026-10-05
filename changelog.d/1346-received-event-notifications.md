---
section: Added
---
- **Wire, Rust and Python API:** an Event Log can record the event
  notifications the server receives, opted in with
  `EventLogObject::set_log_received_notifications` or
  `add_event_log(log_received_notifications=True)`; each source is held to
  5 records a second (#1346).
