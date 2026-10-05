#!/usr/bin/env python3
"""Require CI to have passed on the release commit (#943, #1472).

    ci_gate.py --commit SHA [--wait SECONDS] [--warn-only]

Reads the GitHub Actions runs of the commit and their check runs through the
API (/actions/runs?head_sha=, then each run's check suite). The release needs:

- in the newest run of .github/workflows/ci.yml on the commit that ran MSRV
  and audit-deny, the check runs `CI OK`, `MSRV (Linux native)` and `Cargo
  Audit + Deny` all succeeded. CI runs those two heavy jobs on tags, pushes to
  main, PRs to main, the weekly run and manual runs, and skips them on PRs to
  dev and pushes to dev, whose `CI OK` passes without them. So a commit can
  carry several `CI OK` check runs, such as a dev→main PR's head with dev's
  lean push run and the PR's heavy run, and only a run that ran the heavy jobs
  counts. A tag push always starts one on the tag's commit;
- in the newest run of .github/workflows/native-tests.yml on the commit,
  `Native OK` succeeded.

Only this repository's runs count, not a fork's pull request runs, and only
check runs that GitHub Actions created. Within a run, the latest check run of
each name counts, so a re-run replaces the attempt it re-ran. Of several runs,
the newest (by the start of its latest attempt) counts, so an older success
can't hide a newer failure.

- That run is still going, or there is no such run yet: wait, up to --wait
  seconds. A tag push starts CI's run on the tag's commit at the same time as
  the release.
- Any of its named check runs finished other than successfully, or is missing
  from a finished run: fail at once.

--warn-only (dry runs) checks once and only warns.

Environment: GITHUB_TOKEN, with actions: read and checks: read, and
GITHUB_REPOSITORY, which Actions sets.
"""

import argparse
import os
import sys
import time

from release_api import GitHub, HttpFailure, ReleaseError

POLL = 30  # seconds between reads; tests set it to 0
PAGE = 100
CI = ".github/workflows/ci.yml"
NATIVE = ".github/workflows/native-tests.yml"
CI_OK, MSRV, AUDIT, NATIVE_OK = "CI OK", "MSRV (Linux native)", "Cargo Audit + Deny", "Native OK"
HEAVY = (MSRV, AUDIT)
ACTIONS_APP = "github-actions"


def paged(gh, url, key):
    """Every item under key of a paged list, at PAGE items a page."""
    found = []
    for page in range(1, 21):
        batch = gh.http.call("GET", f"{url}&per_page={PAGE}&page={page}").get(key) or []
        found += batch
        if len(batch) < PAGE:
            return found
    raise ReleaseError(f"{url} has more than 20 pages")


def workflow_runs(gh, commit):
    return paged(gh, f"{gh.api}/actions/runs?head_sha={commit}", "workflow_runs")


def check_runs(gh, run):
    """{name: check run}: the latest check run of each name that GitHub
    Actions created in run's check suite."""
    found = {}
    for check in paged(gh, f"{gh.api}/check-suites/{run['check_suite_id']}/check-runs?filter=latest",
                       "check_runs"):
        if (check.get("app") or {}).get("slug") != ACTIONS_APP:
            continue
        seen = found.get(check["name"])
        if seen is None or (check.get("started_at") or "", check["id"]) > (seen.get("started_at") or "", seen["id"]):
            found[check["name"]] = check
    return found


def state(check):
    """A check run's conclusion once it finished, else its status; None if missing."""
    if check is None:
        return None
    if check.get("status") != "completed":
        return check.get("status") or "pending"
    return check.get("conclusion") or "unknown"


def ours(runs, repo, path):
    """The runs of the workflow at path on this repository (not a fork's), newest first."""
    mine = [r for r in runs if (r.get("path") or "").split("@")[0] == path
            and (r.get("head_repository") or {}).get("full_name") == repo]
    return sorted(mine, key=lambda r: (r.get("run_started_at") or r.get("created_at") or "", r["id"]),
                  reverse=True)


def verdict(run, checks, names):
    """("pass" | "wait" | "fail", description) for the named check runs of run."""
    states = {name: state(checks.get(name)) for name in names}
    finished = run.get("status") == "completed"
    where = f"run {run['id']} ({run.get('event')} on {run.get('head_branch')}, {run.get('html_url')})"
    shown = ", ".join(f"{name}: {s or 'missing'}" for name, s in states.items())
    if all(s == "success" for s in states.values()):
        return "pass", f"{where}: {shown}"
    terminal = [s for s in states.values() if s not in (None, "queued", "in_progress", "pending", "waiting",
                                                        "requested")]
    if any(s != "success" for s in terminal) or (finished and None in states.values()):
        return "fail", f"{where}: {shown}"
    return "wait", f"{where}: {shown}"


def heavy_ci_run(runs, repo, checks_of):
    """(run, its check runs) for the newest ci.yml run that ran, or may still
    run, MSRV and audit-deny; None if there is none. A run that skipped both,
    or finished without either, is lean."""
    for run in ours(runs, repo, CI):
        checks = checks_of(run)
        heavy = [state(checks.get(name)) for name in HEAVY]
        if all(s == "skipped" for s in heavy):
            continue
        if run.get("status") == "completed" and all(s is None for s in heavy):
            continue
        return run, checks
    return None


def evaluate(runs, repo, checks_of):
    """("pass" | "wait" | "fail", [one line per requirement]). checks_of(run)
    gives a run's {name: check run}."""
    results = []
    heavy = heavy_ci_run(runs, repo, checks_of)
    if heavy is None:
        lean = len(ours(runs, repo, CI))
        results.append(("wait", f"CI: no ci.yml run on this commit ran {MSRV} and {AUDIT} ({lean} that"
                                " skipped them); a tag push starts one"))
    else:
        result, text = verdict(*heavy, (CI_OK, *HEAVY))
        results.append((result, f"CI: {text}"))
    native = ours(runs, repo, NATIVE)
    if not native:
        results.append(("wait", "Native: no native-tests.yml run on this commit; it runs on pushes to dev and"
                                " main and on PRs to them, not on tags"))
    else:
        result, text = verdict(native[0], checks_of(native[0]), (NATIVE_OK,))
        results.append((result, f"Native: {text}"))
    outcomes = {result for result, _ in results}
    overall = "fail" if "fail" in outcomes else "wait" if "wait" in outcomes else "pass"
    return overall, [text for _, text in results]


def read(gh, commit):
    runs = workflow_runs(gh, commit)
    cache = {}

    def checks_of(run):
        if run["id"] not in cache:
            cache[run["id"]] = check_runs(gh, run)
        return cache[run["id"]]

    return evaluate(runs, gh.repo, checks_of)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--commit", required=True)
    parser.add_argument("--wait", type=int, default=0, help="seconds to wait for runs still going")
    parser.add_argument("--warn-only", action="store_true", help="check once and only warn (dry runs)")
    args = parser.parse_args(argv)
    if hasattr(sys.stdout, "reconfigure"):  # not when tests capture it
        sys.stdout.reconfigure(line_buffering=True)
    try:
        gh = GitHub(os.environ["GITHUB_REPOSITORY"], os.environ["GITHUB_TOKEN"])
        deadline = time.monotonic() + args.wait
        shown = None
        while True:
            try:
                result, lines = read(gh, args.commit)
            except HttpFailure as err:
                if not err.uncertain or args.warn_only or time.monotonic() >= deadline:
                    raise
                print(f"reading the runs failed ({err}); trying again")
                time.sleep(POLL)
                continue
            if lines != shown:
                print("\n".join(lines))
                shown = lines
            described = "\n  - ".join(lines)
            if result == "pass":
                print(f"CI passed on {args.commit}")
                return 0
            if args.warn_only:
                print(f"::warning::a release of {args.commit} would need these to pass (not required for a"
                      f" dry run):\n  - {described}")
                return 0
            if result == "fail":
                raise ReleaseError(
                    f"CI failed on {args.commit}:\n  - {described}\nIf that was transient (a flaky test, a"
                    " runner problem), re-run the failed jobs of that run, then the release's failed jobs."
                    " A real failure needs a fix, which goes into a new version.")
            if time.monotonic() >= deadline:
                raise ReleaseError(
                    f"CI hasn't passed on {args.commit} after {args.wait} s:\n  - {described}\nA tag push"
                    " starts ci.yml's heavy run on the tag's commit; native-tests.yml runs only on pushes"
                    " to dev and main and on PRs, so tag a commit that is on dev or main. Re-run the"
                    " release's failed jobs once both have passed.")
            time.sleep(POLL)
    except KeyError as err:
        print(f"::error::{err.args[0]} is not set", file=sys.stderr)
    except ReleaseError as err:
        print(f"::error::{err}", file=sys.stderr)
    return 1


if __name__ == "__main__":
    sys.exit(main())
