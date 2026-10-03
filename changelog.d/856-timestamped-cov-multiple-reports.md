---
section: Fixed
---
- Timestamped COV-multiple reports now carry each change's actual commit time
  instead of the time the notification was prepared. Changes are kept until a
  notification carrying them is transmitted.
  - **Capture points:** network WriteProperty and WritePropertyMultiple,
    `write_local`, Staging target writes and source completion, Binary Lighting
    terminal transitions and committed intrinsic transitions capture under the
    database write guard. WritePropertyMultiple captures every successful
    attempt as it commits, so a request that writes a value out and back, or
    fails after a committed prefix, conveys each change. Life Safety objects
    capture exactly the properties each mutation changed, on every path that
    fans them out, and LifeSafetyOperation changes do too.
  - **Delivery:** any notification to a context also carries that context's other
    pending timestamped changes, earlier changes first, per reference (for example
    A→B→A, also within one clock tick). The header timestamp names the latest
    timestamped change conveyed. An explicit untimestamped selector keeps its
    coordinate untimestamped even when it did not qualify in that round.
  - **Max_Notification_Delay:** changes still queued because their notification
    failed or was held back (a failed send, an unacknowledged confirmed report,
    DISABLE_INITIATION) go out once the context's delay has passed since the
    earliest of them, without waiting for another change (§13.1, §13.16.1.1.4).
    Overdue changes go out as soon as nothing blocks them: when communication is
    re-enabled (by request or timer), when a renewal shortens the delay, at the
    end of a confirmed hold-off, or on the Ack of an outstanding report. The
    backstop acts no sooner than one second after the change and otherwise
    retries a blocked context at most once per delay. The delay and the
    backstop's wait are kept only for contexts with timestamped references.
  - **Initial report:** the report after admission is stamped with the admission
    time, taken from the same clock sample the admission check validated. A
    renewal keeps unconveyed changes.
  - **Local bounds:** pending history is capped at an estimate of one notification
    APDU per context, and queued history is trimmed, oldest first, to fit each
    request into the local maximum APDU (latest changes are always sent). This deviates from the Standard's
    additional-notification expectation until splitting lands. Drops are counted
    in the new `CovCounters::timed_changes_dropped` field, which breaks exhaustive
    struct literals.
  - **API:** `CovSubscriptionTable::with_max_apdu_length` is new (#856).
