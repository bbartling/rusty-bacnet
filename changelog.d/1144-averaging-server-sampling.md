---
section: Added
---
- **Breaking Averaging samples taken by the server (behaviour, Rust API):** a
  running server now reads an Averaging object's Object_Property_Reference
  itself, every Window_Interval / Window_Samples seconds, as Clauses 12.5.14
  and 12.5.15 describe (#1144). Before, only the application fed samples and
  Window_Interval was advice to it.
  - Only an object holding a reference is sampled. The first sample comes one
    spacing after the server starts or after any write that empties the window
    (Window_Interval, Window_Samples, Object_Property_Reference, or zero to
    Attempted_Samples, even with the value already held), which also restarts
    the spacing. The spacing never drops below
    `averaging::MIN_SAMPLE_PERIOD` (100 ms); a shorter configured one is
    stretched, so that window covers more than Window_Interval. A pass that
    falls a whole spacing behind takes one sample rather than catching up.
  - A referenced object or property that doesn't exist, an array index on a
    property that isn't an array, any other read error, and a value outside
    the five datatypes Clause 12.5 averages count as missed attempts
    (Attempted_Samples moves, Valid_Samples doesn't). Remote references remain
    refused when written, so every target is local.
  - Each sample reaches property COV subscribers as a write does. The work
    runs on the existing monotonic operation task, which now also never wakes
    in a loop for a deadline an object leaves due.
  - `add_averaging_sample_local` (Rust and Python) keeps working. An object
    without a reference is fed by the application only; on one with a
    reference, an application sample is one more attempt in the window and
    doesn't move the server's spacing, so an application that fed a
    referenced object should stop or clear the reference.
  - New: `ObjectDatabase::sample_due_averaging_objects`, the hidden
    `BACnetObject::take_due_averaging_sample_internal` hook (forwarded by the
    endpoint's source reporter), and `averaging::MIN_SAMPLE_PERIOD`.
