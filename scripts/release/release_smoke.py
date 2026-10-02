#!/usr/bin/env python3
"""Smoke-test the macOS and Windows release artifacts on GitHub-hosted runners (#951).

    release_smoke.py gate --tag v0.12.0 --commit SHA --version 0.12.0 --python 3.11 3.12 3.13 3.14 \
        --notes notes-github.md --assets DIR --ref REF [--throwaway release-smoke-<run id>] \
        [--wait-tag SECONDS] [--timeout SECONDS]
    release_smoke.py discard --name release-smoke-<run id>
    release_smoke.py fetch --release-id ID --sums SHA256 --python 3.11 3.12 3.13 3.14 --out DIR

Forgejo can't run macOS or Windows binaries, and GitHub's runners can't reach
Forgejo (it's on the tailnet only), so the artifacts reach GitHub through the
GitHub draft release that the release copy publishes later.

gate runs in Forgejo's smoke job, after the artifact tests and before anything
is published:
1. stage the draft (release_api.stage): on a release, the draft for --tag,
   which the GitHub copy later publishes unchanged; on a dry run, a throwaway
   draft called --throwaway;
2. dispatch .github/workflows/release-smoke.yml on --ref with the draft's id,
   the sha256 of its SHA256SUMS, the version, the commit, the Pythons, and a
   correlation id that the run's name carries;
3. find that run (the dispatch response names it; otherwise by its name),
   check that it is for the release commit, and poll it every 30 seconds,
   printing each job's progress, for up to --timeout seconds; a run still
   going when the gate fails is cancelled;
4. print every job with its result, link and failed steps, and fail unless
   the run and each expected job succeeded;
5. on a dry run, delete the throwaway draft, whatever happened.
It writes release_id and sums_sha256 to GITHUB_OUTPUT, for the GitHub copy's
--staged-release and --staged-sums.

discard deletes a throwaway draft (Forgejo's clean-up step, in case gate was
killed before it could).

fetch runs in the GitHub workflow's first job, with the job token: it reads the
draft by id, checks that its SHA256SUMS has the sha256 that gate staged,
downloads each macOS and Windows wheel and CLI binary, checks it against
SHA256SUMS, and sorts them into DIR/<platform>/ for the smoke jobs.

Environment (values are never printed): gate and discard need
GH_RELEASE_TOKEN (Contents and Actions read and write); fetch needs
GITHUB_TOKEN. GITHUB_REPO (default jscott3201/rusty-bacnet) names the
repository for gate and discard, GITHUB_REPOSITORY for fetch.
"""

import argparse
import datetime
import os
import re
import secrets
import sys
import time
import urllib.parse
from pathlib import Path

import release_api as api

WORKFLOW = "release-smoke.yml"
RUN_NAME = "Release smoke {}"
POLL = 30  # seconds between polls of the run; tests set it to 0
FIND_POLL = 10  # seconds between looks for the dispatched run
FIND_TIMEOUT = 300
NEW_RUN_READS = 5  # reads of a just-dispatched run that may still be 404
# Each smoke-tested platform: its wheels' platform tag pattern and its CLI binary.
PLATFORMS = {
    "macos-arm64": (re.compile(r"-macosx_\d+_\d+_arm64\.whl$"), "bacnet-macos-arm64"),
    "macos-x86_64": (re.compile(r"-macosx_\d+_\d+_x86_64\.whl$"), "bacnet-macos-amd64"),
    "windows-x86_64": (re.compile(r"-win_amd64\.whl$"), "bacnet-windows-amd64.exe"),
}
# The jobs release-smoke.yml must run, all successfully, for the gate to pass, so
# that a job skipped by mistake can't pass it.
EXPECTED_JOBS = ("Fetch the draft's assets", "Smoke test (macOS arm64)", "Smoke test (macOS x86_64)",
                 "Smoke test (Windows x86_64)")


def write_outputs(**values):
    path = os.environ.get("GITHUB_OUTPUT")
    if path:
        with open(path, "a", encoding="utf-8") as out:
            for key, value in values.items():
                out.write(f"{key}={value}\n")


def runs_url(gh, suffix=""):
    return f"{gh.api}/actions/runs{suffix}"


def get_run(gh, run_id):
    return gh.http.call("GET", runs_url(gh, f"/{run_id}"))


def get_new_run(gh, run_id):
    """A run the dispatch just named. GitHub's API is eventually consistent, so
    it may read as 404 for a moment."""
    for attempt in range(1, NEW_RUN_READS + 1):
        run = gh.http.call("GET", runs_url(gh, f"/{run_id}"), ok404=True)
        if run is not None:
            return run
        if attempt < NEW_RUN_READS:
            time.sleep(FIND_POLL)
    raise api.ReleaseError(f"the dispatch answered with run {run_id}, but GitHub still has no such run after"
                           f" {NEW_RUN_READS} reads")


def list_jobs(gh, run_id):
    # Four jobs: one page is enough.
    return gh.http.call("GET", runs_url(gh, f"/{run_id}/jobs?filter=latest&per_page=100"))["jobs"]


def find_run(gh, correlation, since, timeout=None):
    """The workflow_dispatch run of WORKFLOW named for correlation, created at or
    after since, polling until timeout; None if it doesn't appear."""
    name = RUN_NAME.format(correlation)
    query = urllib.parse.urlencode({"event": "workflow_dispatch", "per_page": 100,
                                    "created": f">={since:%Y-%m-%dT%H:%M:%SZ}"})
    deadline = time.monotonic() + (FIND_TIMEOUT if timeout is None else timeout)
    while True:
        runs = gh.http.call("GET", f"{gh.api}/actions/workflows/{WORKFLOW}/runs?{query}")["workflow_runs"]
        found = [r for r in runs if r.get("display_title") == name]
        if found:
            return min(found, key=lambda r: r["id"])
        if time.monotonic() >= deadline:
            return None
        time.sleep(FIND_POLL)


def dispatch(gh, ref, inputs):
    """Dispatch WORKFLOW on ref and return its run. A dispatch whose response
    is lost may still have started a run, so the run is looked for by name
    before the dispatch is sent again."""
    correlation = inputs["correlation_id"]
    # Two minutes' slack for the clocks of the runner and GitHub.
    since = datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(minutes=2)
    url = f"{gh.api}/actions/workflows/{WORKFLOW}/dispatches"
    body = {"ref": ref, "inputs": inputs, "return_run_details": True}
    for attempt in range(1, 4):
        try:
            response = gh.http.call("POST", url, body, retry=False)
        except api.HttpFailure as err:
            if not err.uncertain or attempt == 3:
                raise api.ReleaseError(f"dispatching {WORKFLOW} on {ref} failed: {err}") from err
            print(f"dispatching failed ({err}); looking for the run before trying again")
            run = find_run(gh, correlation, since, timeout=60)
            if run is not None:
                return run
            continue
        if isinstance(response, dict) and response.get("workflow_run_id"):
            # The dispatched run's own id. Until GitHub evaluates run-name, the
            # run is called after the workflow (dry run 102), so check its
            # workflow and event, not its name.
            run = get_new_run(gh, response["workflow_run_id"])
            if run.get("path") != f".github/workflows/{WORKFLOW}" or run.get("event") != "workflow_dispatch":
                raise api.ReleaseError(f"the dispatch answered with run {run['id']}, a {run.get('event')} run of"
                                       f" {run.get('path')}, not a workflow_dispatch run of {WORKFLOW}")
            return run
        run = find_run(gh, correlation, since)  # an API version that answers 204
        if run is None:
            raise api.ReleaseError(f"{WORKFLOW} was dispatched on {ref}, but no run named"
                                   f" {RUN_NAME.format(correlation)!r} appeared within {FIND_TIMEOUT} s")
        return run
    raise AssertionError("unreachable")


def job_state(job):
    return job.get("conclusion") or job.get("status")


def cancel(gh, run):
    """Ask GitHub to cancel run; returns what happened, for a message."""
    try:
        gh.http.call("POST", runs_url(gh, f"/{run['id']}/cancel"), b"", retry=False)
        return "cancelled it"
    except api.HttpFailure as err:
        return f"couldn't cancel it ({err})"


def wait(gh, run, timeout):
    """Poll run until it completes, printing each job's progress. Returns (run,
    jobs). At the deadline it fails, and the gate cancels the run."""
    deadline = time.monotonic() + timeout
    seen = {}
    while True:
        run = get_run(gh, run["id"])
        jobs = list_jobs(gh, run["id"])
        for job in sorted(jobs, key=lambda j: j["name"]):
            if seen.get(job["id"]) != job_state(job):
                seen[job["id"]] = job_state(job)
                print(f"  {job['name']}: {job_state(job)}")
        if run["status"] == "completed":
            return run, jobs
        if time.monotonic() >= deadline:
            raise api.ReleaseError(f"the smoke test didn't finish within {timeout} s: {run['html_url']}")
        time.sleep(POLL)


def report(run, jobs):
    """Print the run's jobs, and return the problems that fail the gate."""
    print(f"GitHub smoke run {run['id']}: {run['html_url']}, {run.get('conclusion')}")
    for job in sorted(jobs, key=lambda j: j["name"]):
        print(f"  {job_state(job):<10} {job['name']}  {job.get('html_url', '')}")
        for step in job.get("steps") or []:
            if step.get("conclusion") not in (None, "success", "skipped"):
                print(f"             step {step['number']}, {step['name']}: {step['conclusion']}")
    problems = [] if run.get("conclusion") == "success" else [f"the run's conclusion is {run.get('conclusion')}"]
    names = {job["name"]: job for job in jobs}
    problems += [f"it has no job {name!r}" for name in EXPECTED_JOBS if name not in names]
    problems += [f"{job['name']} is {job_state(job)}" for job in jobs if job.get("conclusion") != "success"]
    return problems


def gate(gh, tags, args):
    name = args.throwaway
    # Before anything else: the clean-up below deletes the draft of this name.
    if name is not None and not name.startswith(api.SMOKE_PREFIX):
        raise api.ReleaseError(f"refusing to use {name} as a throwaway draft; it must start with {api.SMOKE_PREFIX}")
    passed = False
    run = None
    try:
        if name is None:
            api.check_tag(tags, args.tag, args.commit, args.wait_tag, dry_run=False)
        release, sums = api.stage(gh, args.tag, args.notes.read_text(encoding="utf-8"), args.assets,
                                  args.commit, throwaway=name)
        write_outputs(release_id=release["id"], sums_sha256=sums)
        correlation = f"{os.environ.get('GITHUB_RUN_ID') or 'local'}-{secrets.token_hex(4)}"
        inputs = {"release_id": str(release["id"]), "sums_sha256": sums, "version": args.version,
                  "commit": args.commit, "pythons": " ".join(args.python), "correlation_id": correlation}
        print(f"dispatching {WORKFLOW} on {args.ref} for draft {release['tag_name']} (id {release['id']}),"
              f" correlation id {correlation}")
        run = dispatch(gh, args.ref, inputs)
        print(f"run {run['id']}: {run['html_url']}")
        if run.get("head_sha") != args.commit:
            # The fetch job refuses to run another commit's scripts, so stop here (the run is cancelled).
            raise api.ReleaseError(f"the smoke run is for {run.get('head_sha')}, the head of {args.ref} now, not the"
                                   f" release commit {args.commit}, and its fetch job runs only the release"
                                   f" commit's scripts. Dispatch the release again on a ref that stays at its"
                                   " commit (a tag always does).")
        run, jobs = wait(gh, run, args.timeout)
        problems = report(run, jobs)
        if problems:
            listed = "".join(f"\n  - {p}" for p in problems)
            raise api.ReleaseError(f"the smoke test failed, so nothing is published:{listed}\n"
                                   f"See {run['html_url']}: each job is one platform, and its failed step says"
                                   " which check failed.")
        print("smoke test passed on every platform")
        passed = True
    except BaseException:
        # A run still going would test a draft that a dry run is about to delete.
        if run is not None and run.get("status") != "completed":
            print(f"stopping the smoke run {run['id']}: {cancel(gh, run)}", file=sys.stderr)
        raise
    finally:
        if name is not None:
            try:
                api.remove_draft(gh, name, [], "smoke test")
            except api.ReleaseError as err:
                message = f"the throwaway draft {name} may still be on GitHub: {err}. Delete it by hand."
                if passed:
                    raise api.ReleaseError(message) from err
                print(f"::error::{message}", file=sys.stderr)  # the gate's own failure follows


def fetch(gh, release_id, sums_sha, pythons, out):
    try:
        release = gh.http.call("GET", f"{gh.api}/releases/{release_id}", ok404=True)
    except api.HttpFailure as err:
        if err.code != 403:
            raise
        release = None
    if release is None:
        raise api.ReleaseError(f"release {release_id} isn't there, or this token can't see it: GitHub shows a"
                               " draft only to a token that can write (contents: write)")
    print(f"release {release_id}: {release['tag_name']}, draft {release.get('draft')}, at"
          f" {release.get('target_commitish')}")
    assets = gh.assets(release)
    if api.SUMS not in assets:
        raise api.ReleaseError(f"release {release_id} has no {api.SUMS}")
    sums_data = gh.download(release, assets[api.SUMS])
    if api.sha256_bytes(sums_data) != sums_sha:
        raise api.ReleaseError(f"the release's {api.SUMS} has sha256 {api.sha256_bytes(sums_data)}, not the"
                               f" staged {sums_sha}; the draft changed after staging")
    sums = api.parse_sums(sums_data.decode())
    for platform, (wheel, cli) in PLATFORMS.items():
        names = [cli]
        for py in pythons:
            tag = "cp" + py.replace(".", "")
            found = sorted(n for n in sums if n.startswith("rusty_bacnet-") and f"-{tag}-{tag}-" in n
                           and wheel.search(n))
            if len(found) != 1:
                raise api.ReleaseError(f"{api.SUMS} lists {len(found)} {platform} wheels for CPython {py}: {found}")
            names += found
        target = out / platform
        target.mkdir(parents=True, exist_ok=True)
        for name in names:
            if name not in sums or name not in assets:
                raise api.ReleaseError(f"release {release_id} lacks {name}")
            data = gh.download(release, assets[name])
            if api.sha256_bytes(data) != sums[name]:
                raise api.ReleaseError(f"{name} doesn't match its {api.SUMS} entry")
            (target / name).write_bytes(data)
            print(f"{platform}: {name} ({len(data)} bytes, sha256 matches {api.SUMS})")
        (target / cli).chmod(0o755)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    sub = parser.add_subparsers(dest="command", required=True)
    g = sub.add_parser("gate", help="stage the draft, run the smoke workflow and wait for it")
    g.add_argument("--tag", required=True)
    g.add_argument("--commit", required=True)
    g.add_argument("--version", required=True, help="the release version, in Cargo's form")
    g.add_argument("--python", nargs="+", required=True, help="the CPython versions with wheels")
    g.add_argument("--notes", type=Path, required=True)
    g.add_argument("--assets", type=Path, required=True)
    g.add_argument("--ref", required=True, help="the git ref to run the smoke workflow on")
    g.add_argument("--throwaway", help="a dry run's draft name (release-smoke-...), deleted afterwards")
    g.add_argument("--wait-tag", type=int, default=0, help="seconds to wait for the mirror's tag")
    g.add_argument("--timeout", type=int, default=3600, help="seconds to wait for the smoke run")
    d = sub.add_parser("discard", help="delete a throwaway draft")
    d.add_argument("--name", required=True)
    f = sub.add_parser("fetch", help="download and check the assets to smoke-test (on GitHub)")
    f.add_argument("--release-id", required=True)
    f.add_argument("--sums", required=True, help="the staged SHA256SUMS's sha256")
    f.add_argument("--python", nargs="+", required=True)
    f.add_argument("--out", type=Path, required=True)
    args = parser.parse_args(argv)
    if hasattr(sys.stdout, "reconfigure"):  # not when tests capture it
        sys.stdout.reconfigure(line_buffering=True)
    try:
        if args.command == "fetch":
            gh = api.GitHub(api.require_env("GITHUB_REPOSITORY", "GitHub Actions sets it."),
                            api.require_env("GITHUB_TOKEN", "Pass the job token."))
            fetch(gh, args.release_id, args.sums, args.python, args.out)
            return 0
        repo = os.environ.get("GITHUB_REPO", api.GITHUB_REPO)
        gh = api.GitHub(repo, api.require_env("GH_RELEASE_TOKEN", api.TOKEN_HINT))
        if args.command == "discard":
            if not args.name.startswith(api.SMOKE_PREFIX):
                raise api.ReleaseError(f"refusing to delete {args.name}; it must start with {api.SMOKE_PREFIX}")
            api.remove_draft(gh, args.name, [], "smoke test")
        else:
            gate(gh, api.GitHub(repo), args)
    except (api.ReleaseError, OSError) as err:
        print(f"::error::{err}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
