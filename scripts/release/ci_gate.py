#!/usr/bin/env python3
"""Require CI's checks to have passed on the release commit (#943).

    ci_gate.py --commit SHA --context "CI / CI OK (push)" [--context ...] \
        [--wait SECONDS] [--warn-only]

Reads Forgejo's combined status for the commit, which keeps the latest status
of each context, so an older success can't hide a newer failure. Every
--context must be `success`:

- `pending`, `skipped` or no status yet: wait, up to --wait seconds. A tag
  push starts CI on the tagged commit at the same time as the release, and a
  dev push's run, which skips the heavy jobs, posts `skipped` under the same
  context names until the tag's run reports;
- `failure`, `error` or anything else: fail at once.

--warn-only (dry runs) checks once and only warns.

Environment: FORGEJO_TOKEN, GITHUB_SERVER_URL and GITHUB_REPOSITORY.
"""

import argparse
import os
import sys
import time

from release_api import Http, HttpFailure, ReleaseError

POLL = 30
LIMIT = 50  # statuses per page
WAITING = ("pending", "skipped", "missing")


def evaluate(statuses, contexts):
    """("pass" | "wait" | "fail", {context: state}) for the required contexts."""
    latest = {s["context"]: s["status"] for s in statuses}
    states = {c: latest.get(c, "missing") for c in contexts}
    if any(s not in ("success", *WAITING) for s in states.values()):
        return "fail", states
    if all(s == "success" for s in states.values()):
        return "pass", states
    return "wait", states


def combined_statuses(http, api, commit):
    """Every context's latest status. The endpoint pages its statuses list, and
    this Forgejo's total_count is the size of the page, so a short page is the last."""
    statuses = []
    for page in range(1, 21):
        combined = http.call("GET", f"{api}/commits/{commit}/status?limit={LIMIT}&page={page}")
        batch = combined.get("statuses") or []
        statuses += batch
        if len(batch) < LIMIT:
            return statuses
    raise ReleaseError(f"{commit} has more than 20 pages of statuses")


def describe(states):
    return ", ".join(f"{c}: {s}" for c, s in states.items())


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--commit", required=True)
    parser.add_argument("--context", action="append", required=True, help="a status that must be success")
    parser.add_argument("--wait", type=int, default=0, help="seconds to wait for pending statuses")
    parser.add_argument("--warn-only", action="store_true", help="check once and only warn (dry runs)")
    args = parser.parse_args(argv)
    if hasattr(sys.stdout, "reconfigure"):  # not when tests capture it
        sys.stdout.reconfigure(line_buffering=True)
    try:
        api = f"{os.environ['GITHUB_SERVER_URL']}/api/v1/repos/{os.environ['GITHUB_REPOSITORY']}"
        http = Http(f"token {os.environ['FORGEJO_TOKEN']}", {"Accept": "application/json"})
        deadline = time.monotonic() + args.wait
        shown = None
        while True:
            try:
                found = combined_statuses(http, api, args.commit)
            except HttpFailure as err:
                if not err.uncertain or args.warn_only or time.monotonic() >= deadline:
                    raise
                print(f"reading the statuses failed ({err}); trying again")
                time.sleep(POLL)
                continue
            verdict, states = evaluate(found, args.context)
            if states != shown:
                print(describe(states))
                shown = states
            if verdict == "pass":
                print(f"CI passed on {args.commit}")
                return 0
            if args.warn_only:
                print(f"::warning::a release of {args.commit} would need these to be success: {describe(states)}"
                      " (not required for a dry run)")
                return 0
            if verdict == "fail":
                raise ReleaseError(
                    f"CI failed on {args.commit}: {describe(states)}. If that was transient (a flaky test,"
                    " a runner problem), re-run the failed CI jobs on this commit, then re-run the release."
                    " A real failure needs a fix, which goes into a new version")
            if time.monotonic() >= deadline:
                raise ReleaseError(
                    f"CI hasn't passed on {args.commit} after {args.wait} s: {describe(states)}. pending or"
                    " missing: the tag's CI run is still going or hasn't started. skipped: the latest run of"
                    " that job on this commit skipped it, as a dev push does, and the tag's run hasn't"
                    " reported yet (or reported before the run that skipped it; re-run the tag's CI run"
                    " then). Re-run the release once the tag's CI run has passed")
            time.sleep(POLL)
    except KeyError as err:
        print(f"::error::{err.args[0]} is not set", file=sys.stderr)
    except ReleaseError as err:
        print(f"::error::{err}", file=sys.stderr)
    return 1


if __name__ == "__main__":
    sys.exit(main())
