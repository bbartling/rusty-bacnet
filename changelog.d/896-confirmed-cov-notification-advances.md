---
section: Fixed
---
- A confirmed COV notification now advances its subscriber's baseline only when
  the subscriber acknowledges it (#896). Before, the baseline moved when the
  notification was admitted, before its first transmission, and stayed there if
  every retry went unanswered or the subscriber answered with an Error. Since
  COV criteria report only actual changes (#889), that change was then never
  re-sent until the value changed again. Now:
  - Each subscription, and each whole COV-multiple context, has one outstanding
    confirmed report. Changes made while it is outstanding wait. A renewal, a
    route change or a re-subscription replaces it: the old incarnation's report
    stops retrying and can no longer complete the new one, so the initial report
    the standard requires is not held behind it.
  - The Ack re-evaluates the subscription or context through the usual fanout,
    so the current values, including Status_Flags and every timestamped change
    held meanwhile, follow in one notification if they differ from what was
    acknowledged. An unchanged value sends nothing. Under DCC this follow-up is
    dropped like any other fanout.
  - Exhausted retries and an Error, Reject or Abort answer leave the baseline
    alone and hold the subscription or context off for one full retry cycle
    (the retry timeout times the first attempt and every retry). Fanouts inside
    the hold-off send nothing. The first one after it reports the change again;
    for a context, it re-evaluates every reference, whatever object it was for.
    Nothing re-sends by itself, so an unreachable or refusing subscriber costs
    at most one delivery attempt per hold-off. Shutdown clears the outstanding
    report without one.
  - Timestamped COV-multiple history retires on the Ack instead of the first
    transmission, and returns to its queue otherwise.
  - A context whose report is replaced while outstanding or owed re-evaluates
    all its references, so a held change still reaches a new route, and newly
    listed references still get their first report. Such a follow-up can repeat
    changes the replaced report already delivered, and it reports the current
    value of each kept untimestamped reference the replaced report carried, since
    that report may have reached the subscriber and a value that went back to
    the old baseline would otherwise never be re-sent (#923). If a failed report
    did arrive without being replaced, a value that goes back during the hold-off
    is still not re-sent; that gap is accepted.
  Peer and global in-flight limits, event budgets and the unconfirmed path are
  unchanged. Re-reporting after the standard's retries end is local policy.
