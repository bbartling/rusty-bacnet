---
section: Added
---
- **Breaking Averaging sample window (wire, Rust and Python API):** the
  Averaging object now serves Window_Interval and Window_Samples and computes
  its statistics over a sliding window, as Clause 12.5 describes (#1092).
  Before, it averaged every sample since creation and read 0.0 before the
  first one.
  - Minimum_Value, Maximum_Value and Average_Value cover the valid samples
    among the most recent Window_Samples attempts. Attempted_Samples counts
    the attempts in the window, so it stops at Window_Samples, and
    Valid_Samples the valid ones. With no valid sample in the window the
    statistics read positive infinity, negative infinity and NaN, where they
    read 0.0 before.
  - Window_Interval (Unsigned seconds, 900 by default) and Window_Samples (15
    by default) are in Property_List, RPM ALL and REQUIRED, and writable in
    the property metadata and the PICS, as is Attempted_Samples. A write of
    either window row, of Object_Property_Reference, or of zero to
    Attempted_Samples empties the window, even when the value doesn't change.
    A zero Window_Interval, a Window_Samples of zero or above 1440
    (`averaging::MAX_WINDOW_SAMPLES`, which bounds the buffer at one sample a
    minute for a day), and a nonzero Attempted_Samples fail with
    VALUE_OUT_OF_RANGE and change nothing.
  - The object has no clock: each sample fills the next slot, and
    Window_Interval tells the application how often to sample. The server
    still doesn't sample Object_Property_Reference itself.
  - `BACnetServer::add_averaging_sample_local` and
    `BACnetObject::add_averaging_sample_internal` now take
    `Option<PropertyValue>`: `None` records an attempt that produced no value,
    which counts toward Attempted_Samples but not Valid_Samples. Python's
    `add_averaging_sample_local` takes `None` the same way. New on
    `AveragingObject`: `add_missed_sample`, `window_interval`,
    `window_samples`, `set_window_interval` and `set_window_samples`; the
    setters and `set_object_property_reference` also empty the window. Python's
    `add_averaging` takes keyword-only `window_interval` and `window_samples`.
  - COV needed no server change: a property subscription compares a NaN or
    infinite REAL by its bits, so a move to or from an empty window's value
    is always reported, whatever the increment, and staying at it never is.
