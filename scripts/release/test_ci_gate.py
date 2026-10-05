#!/usr/bin/env python3
"""Unit tests for ci_gate.py (no network): python3 -m unittest discover -s scripts/release"""

import contextlib
import io
import itertools
import os
import re
import unittest
from pathlib import Path
from unittest import mock

import ci_gate as gate
import release_api

gate.POLL = 0
REPO = "o/r"
COMMIT = "c0ffee"
IDS = itertools.count(1)
ROOT = Path(__file__).resolve().parents[2]


def check(name, conclusion="success", status="completed", started="2026-10-04T10:00:00Z", app="github-actions"):
    return {"id": next(IDS), "name": name, "status": status, "conclusion": conclusion if status == "completed" else None,
            "started_at": started, "app": {"slug": app}}


def run(path, started, checks, status="completed", event="push", repo=REPO, branch="dev", sha=COMMIT):
    return {"id": next(IDS), "path": path, "run_started_at": started, "status": status, "event": event,
            "head_branch": branch, "head_sha": sha, "head_repository": {"full_name": repo},
            "html_url": "https://x.invalid/run", "check_suite_id": next(IDS), "checks": checks}


def ci(started, heavy="success", ci_ok="success", **kwargs):
    """A ci.yml run: heavy is MSRV's and audit-deny's conclusion, "skipped" for a lean run."""
    return run(gate.CI, started, [check(gate.CI_OK, ci_ok), check(gate.MSRV, heavy), check(gate.AUDIT, heavy)],
               **kwargs)


def native(started, result="success", **kwargs):
    return run(gate.NATIVE, started, [check(gate.NATIVE_OK, result)], **kwargs)


def checks_of(r):
    found = {}
    for c in r["checks"]:
        if c["app"]["slug"] == gate.ACTIONS_APP:
            found[c["name"]] = c
    return found


def evaluate(*runs):
    return gate.evaluate(list(runs), REPO, checks_of)


def evaluate_tag(*runs, tag="v1.0.0"):
    return gate.evaluate(list(runs), REPO, checks_of, tag, COMMIT)


class EvaluateTests(unittest.TestCase):
    def test_tag_commit_with_a_lean_dev_run_and_the_tags_heavy_run(self):
        result, lines = evaluate(ci("2026-10-04T10:00:00Z", heavy="skipped"), ci("2026-10-04T09:00:00Z"),
                                 native("2026-10-04T08:00:00Z"))
        self.assertEqual(result, "pass", lines)
        self.assertIn("MSRV (Linux native): success", lines[0])

    def test_a_newer_lean_ci_ok_is_not_enough(self):
        # A dev→main PR's head: dev's lean push run is newer than any heavy one.
        result, lines = evaluate(ci("2026-10-04T10:00:00Z", heavy="skipped"), native("2026-10-04T08:00:00Z"))
        self.assertEqual(result, "wait")
        self.assertIn("no ci.yml run on this commit ran MSRV", lines[0])

    def test_the_heavy_run_still_going_waits(self):
        going = run(gate.CI, "2026-10-04T10:00:00Z", [check(gate.CI_OK, status="queued"),
                                                      check(gate.MSRV, status="in_progress"),
                                                      check(gate.AUDIT)], status="in_progress")
        result, _ = evaluate(going, ci("2026-10-04T09:00:00Z", heavy="skipped"), native("2026-10-04T08:00:00Z"))
        self.assertEqual(result, "wait")

    def test_a_just_started_run_without_check_runs_waits(self):
        fresh = run(gate.CI, "2026-10-04T10:00:00Z", [], status="queued")
        result, lines = evaluate(fresh, ci("2026-10-04T09:00:00Z"), native("2026-10-04T08:00:00Z"))
        self.assertEqual(result, "wait")
        self.assertIn("CI OK: missing", lines[0])

    def test_a_heavy_failure_fails(self):
        result, lines = evaluate(ci("2026-10-04T10:00:00Z", heavy="failure", ci_ok="failure"),
                                 native("2026-10-04T08:00:00Z"))
        self.assertEqual(result, "fail")
        self.assertIn("MSRV (Linux native): failure", lines[0])

    def test_an_older_success_cant_hide_a_newer_failure(self):
        result, _ = evaluate(ci("2026-10-04T10:00:00Z", heavy="failure", ci_ok="failure"),
                             ci("2026-10-04T09:00:00Z"), native("2026-10-04T08:00:00Z"))
        self.assertEqual(result, "fail")
        result, _ = evaluate(ci("2026-10-04T09:00:00Z"), native("2026-10-04T10:00:00Z", "failure"),
                             native("2026-10-04T08:00:00Z"))
        self.assertEqual(result, "fail")

    def test_a_finished_run_missing_ci_ok_fails(self):
        broken = run(gate.CI, "2026-10-04T10:00:00Z", [check(gate.MSRV), check(gate.AUDIT)])
        result, lines = evaluate(broken, native("2026-10-04T08:00:00Z"))
        self.assertEqual(result, "fail")
        self.assertIn("CI OK: missing", lines[0])

    def test_a_finished_run_without_heavy_check_runs_is_lean(self):
        older_workflow = run(gate.CI, "2026-10-04T10:00:00Z", [check(gate.CI_OK)])
        result, _ = evaluate(older_workflow, ci("2026-10-04T09:00:00Z"), native("2026-10-04T08:00:00Z"))
        self.assertEqual(result, "pass")

    def test_a_forks_runs_and_other_apps_check_runs_dont_count(self):
        fork = ci("2026-10-04T10:00:00Z", repo="someone/fork", event="pull_request")
        result, _ = evaluate(fork, native("2026-10-04T08:00:00Z"))
        self.assertEqual(result, "wait")
        impostor = run(gate.CI, "2026-10-04T10:00:00Z", [check(gate.CI_OK, app="other"),
                                                         check(gate.MSRV), check(gate.AUDIT)])
        result, lines = evaluate(impostor, native("2026-10-04T08:00:00Z"))
        self.assertEqual(result, "fail")
        self.assertIn("CI OK: missing", lines[0])

    def test_other_workflows_dont_count(self):
        pages = run(".github/workflows/docs-pages.yml", "2026-10-04T10:00:00Z", [check(gate.CI_OK)])
        result, lines = evaluate(pages, native("2026-10-04T08:00:00Z"))
        self.assertEqual(result, "wait")
        self.assertIn("(0 that skipped them)", lines[0])

    def test_native_ok_is_required(self):
        result, lines = evaluate(ci("2026-10-04T09:00:00Z"))
        self.assertEqual(result, "wait")
        self.assertIn("no native-tests.yml run on this commit", lines[1])
        going = run(gate.NATIVE, "2026-10-04T10:00:00Z", [check(gate.NATIVE_OK, status="queued")],
                    status="in_progress")
        self.assertEqual(evaluate(ci("2026-10-04T09:00:00Z"), going)[0], "wait")
        self.assertEqual(evaluate(ci("2026-10-04T09:00:00Z"), native("2026-10-04T10:00:00Z", "cancelled"))[0],
                         "fail")


class TagTests(unittest.TestCase):
    """A release (--tag) needs the run that the tag's push started."""

    def test_the_tags_own_push_run_passes(self):
        result, lines = evaluate_tag(ci("2026-10-04T10:00:00Z", heavy="skipped"),
                                     ci("2026-10-04T09:00:00Z", branch="v1.0.0"), native("2026-10-04T08:00:00Z"))
        self.assertEqual(result, "pass", lines)
        self.assertIn("push on v1.0.0", lines[0])

    def test_another_heavy_run_doesnt_stand_in_for_the_tags(self):
        # A push to main, a PR to main or a manual run ran the heavy jobs too.
        for other in (ci("2026-10-04T10:00:00Z", branch="main"),
                      ci("2026-10-04T10:00:00Z", event="pull_request", branch="v1.0.0"),
                      ci("2026-10-04T10:00:00Z", event="workflow_dispatch", branch="v1.0.0"),
                      ci("2026-10-04T10:00:00Z", branch="v0.9.0"),
                      ci("2026-10-04T10:00:00Z", branch="v1.0.0", sha="beef")):
            with self.subTest(event=other["event"], branch=other["head_branch"], sha=other["head_sha"]):
                result, lines = evaluate_tag(other, native("2026-10-04T08:00:00Z"))
                self.assertEqual(result, "wait")
                self.assertIn("no ci.yml run of the push of v1.0.0 on this commit yet", lines[0])

    def test_the_tags_run_still_going_waits_and_its_failure_fails(self):
        going = run(gate.CI, "2026-10-04T10:00:00Z", [check(gate.CI_OK, status="queued"),
                                                      check(gate.MSRV, status="in_progress"), check(gate.AUDIT)],
                    status="in_progress", branch="v1.0.0")
        self.assertEqual(evaluate_tag(going, native("2026-10-04T08:00:00Z"))[0], "wait")
        failed = ci("2026-10-04T10:00:00Z", heavy="failure", ci_ok="failure", branch="v1.0.0")
        self.assertEqual(evaluate_tag(failed, ci("2026-10-04T09:00:00Z", branch="main"),
                                      native("2026-10-04T08:00:00Z"))[0], "fail")

    def test_a_tag_run_that_skipped_the_heavy_jobs_fails(self):
        # If ci.yml ever stopped running them on tags, the gate says so at once.
        lean = ci("2026-10-04T10:00:00Z", heavy="skipped", branch="v1.0.0")
        result, lines = evaluate_tag(lean, native("2026-10-04T08:00:00Z"))
        self.assertEqual(result, "fail")
        self.assertIn("MSRV (Linux native): skipped", lines[0])

    def test_native_ok_is_still_required(self):
        result, lines = evaluate_tag(ci("2026-10-04T09:00:00Z", branch="v1.0.0"))
        self.assertEqual(result, "wait")
        self.assertIn("no native-tests.yml run", lines[1])


def job_names(path):
    """The job-level `name:` values of a workflow file."""
    return set(re.findall(r"^    name: (.+?)\s*$", (ROOT / path).read_text(encoding="utf-8"), re.MULTILINE))


class WorkflowTests(unittest.TestCase):
    """The names the gate relies on exist in the workflows, so a rename fails
    here, not after a tag's 60-minute wait."""

    def test_ci_yml_has_the_jobs_the_gate_reads(self):
        names = job_names(gate.CI)
        for name in (gate.CI_OK, gate.MSRV, gate.AUDIT):
            with self.subTest(name=name):
                self.assertIn(name, names, f"{gate.CI} has no job named {name!r}; update ci_gate.py with it")

    def test_native_tests_yml_has_native_ok(self):
        self.assertIn(gate.NATIVE_OK, job_names(gate.NATIVE))

    def test_ci_yml_runs_on_tag_pushes(self):
        # A release needs the run that its tag's push starts.
        text = (ROOT / gate.CI).read_text(encoding="utf-8")
        self.assertRegex(text, r'(?m)^  push:\n(?:    .*\n)*?    tags: \["v\*"\]')

    def test_the_job_name_reader_reads_names(self):
        self.assertIn("Lint", job_names(gate.CI))
        self.assertNotIn("Rustfmt", job_names(gate.CI))  # a step's name


class ReadTests(unittest.TestCase):
    """read() against a fake API: paging, the check-suite endpoint, latest per name."""

    def fake(self, runs, suites):
        calls = []

        def call(method, url, **kwargs):
            calls.append(url)
            page = int(url.rsplit("page=", 1)[1])
            if "/actions/runs?head_sha=c0ffee" in url:
                return {"workflow_runs": runs[(page - 1) * gate.PAGE:page * gate.PAGE]}
            suite = int(url.split("/check-suites/")[1].split("/")[0])
            self.assertIn("filter=latest", url)
            return {"check_runs": suites[suite][(page - 1) * gate.PAGE:page * gate.PAGE]}

        gh = release_api.GitHub(REPO, "t")
        return gh, calls, mock.patch.object(gh.http, "call", call)

    def test_runs_are_read_page_by_page_and_the_latest_check_run_counts(self):
        filler = [run(".github/workflows/other.yml", "2026-10-04T07:00:00Z", []) for _ in range(gate.PAGE)]
        heavy, nat = ci("2026-10-04T09:00:00Z"), native("2026-10-04T08:00:00Z")
        # A re-run attempt's CI OK, started later, replaces the failed first attempt's.
        suites = {heavy["check_suite_id"]: [check(gate.CI_OK, "failure", started="2026-10-04T09:00:00Z"),
                                            check(gate.CI_OK, started="2026-10-04T09:30:00Z"),
                                            check(gate.MSRV), check(gate.AUDIT)],
                  nat["check_suite_id"]: nat["checks"]}
        gh, calls, patch = self.fake(filler + [heavy, nat], suites)
        with patch:
            result, lines = gate.read(gh, "c0ffee")
        self.assertEqual(result, "pass", lines)
        self.assertEqual(sum("/actions/runs?" in url for url in calls), 2)
        self.assertTrue(any(f"/check-suites/{heavy['check_suite_id']}/check-runs" in url for url in calls))


class MainTests(unittest.TestCase):
    ENV = {"GITHUB_REPOSITORY": REPO, "GITHUB_TOKEN": "t"}

    def run_main(self, argv, results, env=None):
        out, err = io.StringIO(), io.StringIO()
        answers = iter(results)
        with mock.patch.dict(os.environ, self.ENV if env is None else env, clear=True), \
                mock.patch.object(gate, "read", lambda gh, commit, tag=None: next(answers)), \
                contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            code = gate.main(argv)
        return code, out.getvalue(), err.getvalue()

    def test_waits_until_it_passes(self):
        code, out, _ = self.run_main(["--commit", "c0ffee", "--wait", "60"],
                                     [("wait", ["CI: going"]), ("wait", ["CI: going"]), ("pass", ["CI: ok"])])
        self.assertEqual(code, 0)
        self.assertEqual(out.count("CI: going"), 1)  # printed when it changes
        self.assertIn("CI passed on c0ffee", out)

    def test_a_failure_fails_at_once(self):
        code, _, err = self.run_main(["--commit", "c0ffee", "--wait", "60"], [("fail", ["CI: MSRV failure"])])
        self.assertEqual(code, 1)
        self.assertIn("CI failed on c0ffee", err)
        self.assertIn("re-run the failed jobs of that run", err)

    def test_the_deadline_fails(self):
        code, _, err = self.run_main(["--commit", "c0ffee"], [("wait", ["Native: none"])])
        self.assertEqual(code, 1)
        self.assertIn("CI hasn't passed on c0ffee after 0 s", err)

    def test_warn_only_checks_once_and_warns(self):
        code, out, _ = self.run_main(["--commit", "c0ffee", "--warn-only", "--wait", "60"],
                                     [("fail", ["CI: failure"])])
        self.assertEqual(code, 0)
        self.assertIn("::warning::a release of c0ffee would need these to pass", out)

    def test_the_tag_reaches_read(self):
        seen = []
        out = io.StringIO()
        with mock.patch.dict(os.environ, self.ENV, clear=True), \
                mock.patch.object(gate, "read", lambda gh, commit, tag=None: seen.append(tag) or ("pass", ["ok"])), \
                contextlib.redirect_stdout(out):
            self.assertEqual(gate.main(["--commit", "c0ffee", "--tag", "v1.0.0"]), 0)
            self.assertEqual(gate.main(["--commit", "c0ffee", "--warn-only"]), 0)
        self.assertEqual(seen, ["v1.0.0", None])

    def test_a_missing_token_fails(self):
        code, _, err = self.run_main(["--commit", "c0ffee"], [], env={"GITHUB_REPOSITORY": REPO})
        self.assertEqual(code, 1)
        self.assertIn("GITHUB_TOKEN is not set", err)


if __name__ == "__main__":
    unittest.main()
