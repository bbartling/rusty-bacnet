#!/usr/bin/env python3
"""Unit tests for release_smoke.py (no network): python3 -m unittest discover -s scripts/release"""

import argparse
import contextlib
import io
import os
import re
import tempfile
import unittest
from pathlib import Path
from unittest import mock

import release_api as api
import release_smoke as smoke
from test_release_api import COMMIT, FakeHost, writes

api.RETRY_DELAY = 0
smoke.POLL = smoke.FIND_POLL = 0
WORKFLOW_FILE = Path(__file__).resolve().parents[2] / ".github" / "workflows" / "release-smoke.yml"
API = "https://api.invalid/repos/o/r"
PYTHONS = ["3.11", "3.12"]


def job(name, conclusion="success", status="completed", steps=()):
    return {"id": hash(name) & 0xFFFF, "name": name, "status": status, "conclusion": conclusion,
            "html_url": f"https://gh.invalid/job/{name}", "steps": list(steps)}


GOOD_JOBS = [job(name) for name in smoke.EXPECTED_JOBS]


class FakeGitHub(FakeHost):
    """FakeHost's releases, plus the Actions endpoints that release_smoke.py calls
    through http.call. Each dispatch creates a run, which like GitHub's is called
    after the workflow until its run-name (the correlation id) is evaluated, for
    `title_delay` reads; it then goes through `states` (status, conclusion) one
    poll at a time."""

    label = "GitHub"

    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.api = API
        self.http = self
        self.requests = []
        self.dispatch_errors = []  # raised by successive dispatch POSTs, before (lost) or instead of a run
        self.return_details = True
        self.title_delay = 1  # reads of a new run that still show the workflow's name
        self.path = ".github/workflows/release-smoke.yml"  # the dispatched run's workflow
        self.list_delay = 0  # polls of the run list before a new run shows up
        self.states = [("completed", "success")]
        self.jobs = GOOD_JOBS
        self.head_sha = COMMIT
        self.runs = {}

    def call(self, method, url, body=None, ok404=False, retry=True, **kwargs):
        path = url.removeprefix(API)
        self.requests.append((method, path.split("?")[0], body))
        if method == "POST" and path.endswith("/dispatches"):
            return self._dispatch(body)
        if method == "GET" and path.startswith("/actions/workflows/release-smoke.yml/runs?"):
            if self.list_delay:
                self.list_delay -= 1
                return {"workflow_runs": []}
            return {"workflow_runs": [self._read(r) for r in self.runs.values()]}
        if m := re.fullmatch(r"/actions/runs/(\d+)", path):
            run = self.runs[int(m[1])]
            if run["status"] != "completed" and self.states:
                run["status"], run["conclusion"] = self.states.pop(0)
            return self._read(run)
        if re.fullmatch(r"/actions/runs/\d+/jobs\?.*", path):
            return {"jobs": self.jobs}
        if method == "POST" and re.fullmatch(r"/actions/runs/\d+/cancel", path):
            return b""
        if m := re.fullmatch(r"/releases/(\d+)", path):
            found = [r for r in self.releases if r["id"] == int(m[1])]
            if not found and ok404:
                return None
            return dict(found[0])
        raise AssertionError(f"unexpected request {method} {url}")

    def _dispatch(self, body):
        error = self.dispatch_errors.pop(0) if self.dispatch_errors else None
        if error == "refused":
            raise api.HttpFailure("POST dispatches returned HTTP 422: no such workflow", 422)
        run_id = 9000 + len(self.runs)
        self.runs[run_id] = {"id": run_id, "name": f"Release smoke {body['inputs']['correlation_id']}",
                             "reads": 0, "path": self.path, "event": "workflow_dispatch", "status": "queued", "conclusion": None, "head_sha": self.head_sha,
                             "html_url": f"https://gh.invalid/run/{run_id}", "inputs": body["inputs"],
                             "ref": body["ref"]}
        if error == "lost":
            raise api.HttpFailure("POST dispatches failed: timed out")
        return {"workflow_run_id": run_id} if self.return_details else b""

    def _read(self, run):
        run["reads"] += 1
        title = "Release smoke test" if run["reads"] <= self.title_delay else run["name"]
        return {**run, "display_title": title}

    def dispatches(self):
        return [r for r in self.requests if r[0] == "POST" and r[1].endswith("/dispatches")]


def quiet(fn, *args, **kwargs):
    out, err = io.StringIO(), io.StringIO()
    with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
        result = fn(*args, **kwargs)
    return result, out.getvalue() + err.getvalue()


INPUTS = {"release_id": "1", "sums_sha256": "ab", "version": "1.0.0", "commit": COMMIT, "pythons": "3.11",
          "correlation_id": "42-cafe"}


class DispatchTests(unittest.TestCase):
    def test_run_details_name_the_run_before_its_run_name_is_set(self):
        # GitHub calls a new run after the workflow until it evaluates
        # run-name; dry run 102 failed on that before the id was trusted.
        gh = FakeGitHub()
        run, _ = quiet(smoke.dispatch, gh, "refs/heads/dev", INPUTS)
        self.assertEqual((run["id"], run["display_title"]), (9000, "Release smoke test"))
        (_, _, body), = gh.dispatches()
        self.assertEqual(body, {"ref": "refs/heads/dev", "inputs": INPUTS, "return_run_details": True})

    def test_without_run_details_the_run_is_found_by_name(self):
        gh = FakeGitHub()
        gh.return_details = False
        gh.list_delay = 2
        gh.title_delay = 3  # listed under the workflow's name at first
        run, _ = quiet(smoke.dispatch, gh, "dev", INPUTS)
        self.assertEqual((run["id"], run["display_title"]), (9000, "Release smoke 42-cafe"))
        self.assertEqual(len([r for r in gh.requests if r[1].endswith("/runs")]), 6)

    def test_new_run_that_reads_as_404_at_first_is_retried(self):
        gh = FakeGitHub()
        original = gh.call
        misses = []

        def call(method, url, *args, **kwargs):
            if method == "GET" and re.search(r"/actions/runs/\d+$", url) and len(misses) < 2:
                misses.append(url)
                assert kwargs.get("ok404")
                return None
            return original(method, url, *args, **kwargs)

        gh.call = call
        run, _ = quiet(smoke.dispatch, gh, "dev", INPUTS)
        self.assertEqual((run["id"], len(misses)), (9000, 2))
        misses.clear()
        gh.call = lambda method, url, *a, **k: None if method == "GET" else original(method, url, *a, **k)
        with self.assertRaisesRegex(api.ReleaseError, "still has no such run after 5 reads"):
            quiet(smoke.dispatch, gh, "dev", INPUTS)

    def test_run_of_another_workflow_is_refused(self):
        gh = FakeGitHub()
        gh.path = ".github/workflows/native-tests.yml"
        with self.assertRaisesRegex(api.ReleaseError, "not a workflow_dispatch run of release-smoke.yml"):
            quiet(smoke.dispatch, gh, "dev", INPUTS)

    def test_lost_response_finds_the_run_instead_of_dispatching_again(self):
        gh = FakeGitHub()
        gh.dispatch_errors = ["lost"]
        run, out = quiet(smoke.dispatch, gh, "dev", INPUTS)
        self.assertEqual(len(gh.dispatches()), 1)
        self.assertEqual(run["id"], 9000)
        self.assertIn("looking for the run before trying again", out)

    def test_refused_dispatch_fails_without_retrying(self):
        gh = FakeGitHub()
        gh.dispatch_errors = ["refused"]
        with self.assertRaisesRegex(api.ReleaseError, "dispatching release-smoke.yml on dev failed"):
            quiet(smoke.dispatch, gh, "dev", INPUTS)
        self.assertEqual(len(gh.dispatches()), 1)

    def test_run_that_never_appears_fails(self):
        gh = FakeGitHub()
        gh.return_details = False
        gh.list_delay = 10**6
        with mock.patch.object(smoke, "FIND_TIMEOUT", 0), \
                self.assertRaisesRegex(api.ReleaseError, "no run named 'Release smoke 42-cafe' appeared"):
            quiet(smoke.dispatch, gh, "dev", INPUTS)


class WaitAndReportTests(unittest.TestCase):
    def dispatched(self, gh):
        run, _ = quiet(smoke.dispatch, gh, "dev", INPUTS)
        return run

    def test_wait_polls_until_completed_and_prints_progress(self):
        gh = FakeGitHub()
        gh.states = [("queued", None), ("in_progress", None), ("in_progress", None), ("completed", "success")]
        steps = iter([[job(n, None, "queued") for n in smoke.EXPECTED_JOBS],
                      [job(n, None, "in_progress") for n in smoke.EXPECTED_JOBS]])
        original = gh.call

        def call(method, url, *args, **kwargs):
            if "/jobs?" in url:
                return {"jobs": next(steps, GOOD_JOBS)}
            return original(method, url, *args, **kwargs)

        gh.call = call
        (run, jobs), out = quiet(smoke.wait, gh, self.dispatched(gh), 60)
        self.assertEqual((run["status"], run["conclusion"]), ("completed", "success"))
        for state in ("queued", "in_progress", "success"):
            self.assertIn(f"  Smoke test (Windows x86_64): {state}", out)

    def test_timeout_fails(self):
        gh = FakeGitHub()
        gh.states = []
        with self.assertRaisesRegex(api.ReleaseError, r"didn't finish within 0 s: https://gh.invalid/run/9000"):
            quiet(smoke.wait, gh, self.dispatched(gh), 0)

    def test_report_passes_only_a_complete_success(self):
        run = {"id": 1, "html_url": "u", "conclusion": "success"}
        problems, _ = quiet(smoke.report, run, GOOD_JOBS)
        self.assertEqual(problems, [])
        problems, _ = quiet(smoke.report, run, GOOD_JOBS[:-1])
        self.assertEqual(problems, ["it has no job 'Smoke test (Windows x86_64)'"])
        skipped = GOOD_JOBS[:-1] + [job("Smoke test (Windows x86_64)", "skipped")]
        problems, _ = quiet(smoke.report, run, skipped)
        self.assertEqual(problems, ["Smoke test (Windows x86_64) is skipped"])

    def test_report_names_the_failed_step(self):
        failed = job("Smoke test (macOS x86_64)", "failure", steps=[
            {"number": 1, "name": "Set up job", "conclusion": "success"},
            {"number": 8, "name": "Wheels, CPython 3.11 to 3.14", "conclusion": "failure"},
            {"number": 9, "name": "CLI", "conclusion": "skipped"}])
        jobs = [j for j in GOOD_JOBS if j["name"] != failed["name"]] + [failed]
        problems, out = quiet(smoke.report, {"id": 1, "html_url": "u", "conclusion": "failure"}, jobs)
        self.assertEqual(problems, ["the run's conclusion is failure", "Smoke test (macOS x86_64) is failure"])
        self.assertIn("step 8, Wheels, CPython 3.11 to 3.14: failure", out)
        self.assertNotIn("CLI: skipped", out)

    def test_expected_jobs_are_the_workflows(self):
        text = WORKFLOW_FILE.read_text(encoding="utf-8")
        self.assertIn("name: Fetch the draft's assets", text)
        self.assertIn("name: Smoke test (${{ matrix.name }})", text)
        for expected in smoke.EXPECTED_JOBS[1:]:
            self.assertIn(f"- name: {expected.removeprefix('Smoke test (').removesuffix(')')}\n", text)
        self.assertIn(f"run-name: {smoke.RUN_NAME.format('${{ inputs.correlation_id }}')}\n", text)
        for name in ("release_id", "sums_sha256", "version", "commit", "pythons", "correlation_id"):
            self.assertIn(f"      {name}:\n", text)
        for platform, (_, cli) in smoke.PLATFORMS.items():
            self.assertIn(f"platform: {platform}\n", text)
            self.assertIn(f"cli: {cli}\n", text)


class GateTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.dir = Path(self.tmp.name)
        self.assets = self.dir / "release"
        self.assets.mkdir()
        (self.assets / "x.whl").write_bytes(b"wheel")
        (self.assets / "bacnet-linux-amd64").write_bytes(b"binary")
        (self.dir / "notes.md").write_text("notes")
        self.output = self.dir / "output"
        self.env = mock.patch.dict(os.environ, {"GITHUB_OUTPUT": str(self.output), "GITHUB_RUN_ID": "77"})
        self.env.start()

    def tearDown(self):
        self.env.stop()
        self.tmp.cleanup()

    def args(self, **kwargs):
        values = {"tag": "v1.0.0", "commit": COMMIT, "version": "1.0.0", "python": PYTHONS,
                  "notes": self.dir / "notes.md", "assets": self.assets, "ref": "refs/heads/dev",
                  "throwaway": None, "wait_tag": 0, "timeout": 60}
        values.update(kwargs)
        return argparse.Namespace(**values)

    def tags(self, commit=COMMIT):
        tags = mock.Mock()
        tags.tag_commit.return_value = commit
        return tags

    def test_release_run_stages_the_tags_draft_and_keeps_it(self):
        gh = FakeGitHub()
        _, out = quiet(smoke.gate, gh, self.tags(), self.args())
        release = gh.releases[0]
        self.assertEqual((release["tag_name"], release["draft"]), ("v1.0.0", True))
        (_, _, body), = gh.dispatches()
        inputs = body["inputs"]
        sums = api.sha256_bytes(gh.files()["SHA256SUMS"])
        self.assertEqual({k: v for k, v in inputs.items() if k != "correlation_id"}, {
            "release_id": str(release["id"]), "sums_sha256": sums, "version": "1.0.0", "commit": COMMIT,
            "pythons": "3.11 3.12"})
        self.assertRegex(inputs["correlation_id"], r"^77-[0-9a-f]{8}$")
        self.assertEqual(self.output.read_text(), f"release_id={release['id']}\nsums_sha256={sums}\n")
        self.assertIn("smoke test passed on every platform", out)
        self.assertNotIn(("publish",), gh.calls)

    def test_tag_elsewhere_stops_before_staging(self):
        gh = FakeGitHub()
        with self.assertRaisesRegex(api.ReleaseError, "points at beef"):
            quiet(smoke.gate, gh, self.tags("beef"), self.args())
        self.assertEqual(gh.releases, [])

    def test_throwaway_name_must_be_a_smoke_name(self):
        # The clean-up deletes the throwaway's name, so a tag must never get there.
        gh = FakeGitHub()
        gh.add("v1.0.0", {"x.whl": b"wheel"}, draft=False)
        gh.add("v1.0.0", {}, draft=True)
        with self.assertRaisesRegex(api.ReleaseError, "refusing to use v1.0.0 as a throwaway draft"):
            quiet(smoke.gate, gh, self.tags(), self.args(throwaway="v1.0.0"))
        self.assertEqual(gh.calls, [])
        self.assertEqual(gh.requests, [])
        self.assertEqual(len(gh.releases), 2)

    def test_dry_run_deletes_its_throwaway_draft(self):
        gh = FakeGitHub()
        tags = self.tags()
        _, out = quiet(smoke.gate, gh, tags, self.args(throwaway="release-smoke-77"))
        tags.tag_commit.assert_not_called()
        self.assertEqual(gh.releases, [])
        self.assertEqual(writes(gh)[0], ("create", "release-smoke-77", "Release smoke test release-smoke-77",
                                         COMMIT, True))
        self.assertEqual(writes(gh)[-1], ("delete-release", "release-smoke-77"))
        self.assertIn("smoke test: no release or tag release-smoke-77 is left", out)

    def test_failed_smoke_run_fails_the_gate_and_still_deletes_the_draft(self):
        gh = FakeGitHub()
        gh.states = [("completed", "failure")]
        gh.jobs = GOOD_JOBS[:-1] + [job("Smoke test (Windows x86_64)", "failure")]
        with self.assertRaisesRegex(api.ReleaseError, "the smoke test failed, so nothing is published") as caught:
            quiet(smoke.gate, gh, self.tags(), self.args(throwaway="release-smoke-77"))
        self.assertIn("Smoke test (Windows x86_64) is failure", str(caught.exception))
        self.assertIn("https://gh.invalid/run/9000", str(caught.exception))
        self.assertEqual(gh.releases, [])

    def test_failed_cleanup_after_a_failed_gate_reports_both(self):
        gh = FakeGitHub()
        gh.states = [("completed", "failure")]
        gh.fail_delete_release = True
        with self.assertRaisesRegex(api.ReleaseError, "the smoke test failed"), \
                contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()) as err:
            smoke.gate(gh, self.tags(), self.args(throwaway="release-smoke-77"))
        self.assertIn("::error::the throwaway draft release-smoke-77 may still be on GitHub", err.getvalue())

    def test_failed_cleanup_after_a_passing_gate_fails(self):
        gh = FakeGitHub()
        gh.fail_delete_release = True
        with self.assertRaisesRegex(api.ReleaseError, "release-smoke-77 may still be on GitHub"):
            quiet(smoke.gate, gh, self.tags(), self.args(throwaway="release-smoke-77"))

    def test_timed_out_run_is_cancelled_before_the_draft_goes(self):
        gh = FakeGitHub()
        gh.states = []
        with self.assertRaisesRegex(api.ReleaseError, "didn't finish within 0 s"), \
                contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()) as err:
            smoke.gate(gh, self.tags(), self.args(throwaway="release-smoke-77", timeout=0))
        self.assertIn("stopping the smoke run 9000: cancelled it", err.getvalue())
        cancel = gh.requests.index(("POST", "/actions/runs/9000/cancel", b""))
        deletes = [i for i, r in enumerate(gh.requests) if r[0] == "DELETE"]
        self.assertTrue(all(i > cancel for i in deletes))
        self.assertEqual(gh.releases, [])

    def test_completed_failed_run_isnt_cancelled(self):
        gh = FakeGitHub()
        gh.states = [("completed", "failure")]
        with self.assertRaisesRegex(api.ReleaseError, "the smoke test failed"):
            quiet(smoke.gate, gh, self.tags(), self.args(throwaway="release-smoke-77"))
        self.assertFalse([r for r in gh.requests if r[1].endswith("/cancel")])

    def test_run_of_another_commit_is_stopped(self):
        # Its fetch job would refuse the release commit's scripts anyway.
        gh = FakeGitHub()
        gh.head_sha = "beef"
        gh.states = []  # still queued
        with self.assertRaisesRegex(api.ReleaseError, "the smoke run is for beef, the head of refs/heads/dev now"), \
                contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()) as err:
            smoke.gate(gh, self.tags(), self.args(throwaway="release-smoke-77"))
        self.assertIn("stopping the smoke run 9000: cancelled it", err.getvalue())
        self.assertEqual(gh.releases, [])


def fetch_release(gh, pythons=PYTHONS, drop=(), corrupt=()):
    files = {}
    for platform, cli in (("macosx_11_0_arm64", "bacnet-macos-arm64"), ("macosx_10_12_x86_64", "bacnet-macos-amd64"),
                          ("win_amd64", "bacnet-windows-amd64.exe")):
        files[cli] = cli.encode()
        for py in pythons:
            tag = "cp" + py.replace(".", "")
            files[f"rusty_bacnet-1.0.0-{tag}-{tag}-{platform}.whl"] = f"{tag} {platform}".encode()
    files["bacnet-linux-amd64"] = b"linux"
    files["rusty_bacnet-1.0.0-cp311-cp311-manylinux_2_17_x86_64.manylinux2014_x86_64.whl"] = b"linux wheel"
    sums = api.sums_text({n: api.sha256_bytes(d) for n, d in files.items()}).encode()
    stored = {n: (d + b"!" if n in corrupt else d) for n, d in files.items() if n not in drop}
    release = gh.add("release-smoke-1", {**stored, "SHA256SUMS": sums}, draft=True)
    return release, api.sha256_bytes(sums)


class FetchTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.out = Path(self.tmp.name)

    def tearDown(self):
        self.tmp.cleanup()

    def test_sorts_each_platforms_files_after_checking_them(self):
        gh = FakeGitHub()
        release, sums = fetch_release(gh)
        _, out = quiet(smoke.fetch, gh, str(release["id"]), sums, PYTHONS, self.out)
        self.assertEqual(sorted(p.name for p in (self.out / "macos-x86_64").iterdir()), [
            "bacnet-macos-amd64", "rusty_bacnet-1.0.0-cp311-cp311-macosx_10_12_x86_64.whl",
            "rusty_bacnet-1.0.0-cp312-cp312-macosx_10_12_x86_64.whl"])
        self.assertEqual(len(list((self.out / "windows-x86_64").iterdir())), 3)
        self.assertEqual((self.out / "macos-arm64" / "bacnet-macos-arm64").read_bytes(), b"bacnet-macos-arm64")
        self.assertTrue(os.access(self.out / "macos-arm64" / "bacnet-macos-arm64", os.X_OK))
        self.assertNotIn(("download", "bacnet-linux-amd64"), gh.calls)
        self.assertIn("sha256 matches SHA256SUMS", out)

    def test_other_sums_than_the_staged_one_fail(self):
        gh = FakeGitHub()
        release, _ = fetch_release(gh)
        with self.assertRaisesRegex(api.ReleaseError, "not the staged 00"):
            quiet(smoke.fetch, gh, str(release["id"]), "00", PYTHONS, self.out)

    def test_corrupt_asset_fails(self):
        gh = FakeGitHub()
        release, sums = fetch_release(gh, corrupt={"bacnet-windows-amd64.exe"})
        with self.assertRaisesRegex(api.ReleaseError, "bacnet-windows-amd64.exe doesn't match its SHA256SUMS"):
            quiet(smoke.fetch, gh, str(release["id"]), sums, PYTHONS, self.out)

    def test_missing_wheel_or_asset_fails(self):
        gh = FakeGitHub()
        release, sums = fetch_release(gh)
        with self.assertRaisesRegex(api.ReleaseError, "lists 0 macos-arm64 wheels for CPython 3.13"):
            quiet(smoke.fetch, gh, str(release["id"]), sums, ["3.13"], self.out)
        gh = FakeGitHub()
        release, sums = fetch_release(gh, drop={"bacnet-macos-amd64"})
        with self.assertRaisesRegex(api.ReleaseError, "lacks bacnet-macos-amd64"):
            quiet(smoke.fetch, gh, str(release["id"]), sums, PYTHONS, self.out)

    def test_release_the_token_cant_see_fails_clearly(self):
        # A missing release is 404; a draft that a contents: read token asks for
        # is 403 ("Resource not accessible by integration").
        gh = FakeGitHub()
        with self.assertRaisesRegex(api.ReleaseError, r"can't see it: .*\(contents: write\)"):
            quiet(smoke.fetch, gh, "123", "00", PYTHONS, self.out)
        gh.call = mock.Mock(side_effect=api.HttpFailure("GET returned HTTP 403", 403))
        with self.assertRaisesRegex(api.ReleaseError, r"can't see it: .*\(contents: write\)"):
            quiet(smoke.fetch, gh, "123", "00", PYTHONS, self.out)
        gh.call = mock.Mock(side_effect=api.HttpFailure("GET returned HTTP 401", 401))
        with self.assertRaisesRegex(api.HttpFailure, "HTTP 401"):
            quiet(smoke.fetch, gh, "123", "00", PYTHONS, self.out)


class MainTests(unittest.TestCase):
    def test_discard_refuses_other_names(self):
        with mock.patch.dict(os.environ, {"GH_RELEASE_TOKEN": "t"}, clear=True):
            code, out = quiet(smoke.main, ["discard", "--name", "v1.0.0"])
        self.assertEqual(code, 1)
        self.assertIn("refusing to delete v1.0.0", out)

    def test_discard_needs_the_token(self):
        with mock.patch.dict(os.environ, {}, clear=True):
            code, out = quiet(smoke.main, ["discard", "--name", "release-smoke-1"])
        self.assertEqual(code, 1)
        self.assertIn("GH_RELEASE_TOKEN is not set", out)
        self.assertIn("Actions read and write", out)


if __name__ == "__main__":
    unittest.main()
