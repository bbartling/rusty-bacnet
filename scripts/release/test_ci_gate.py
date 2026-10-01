#!/usr/bin/env python3
"""Unit tests for ci_gate.py (no network): python3 -m unittest discover -s scripts/release"""

import contextlib
import io
import os
import unittest
from unittest import mock

import ci_gate as gate

REQUIRED = ["CI / CI OK (push)", "CI / MSRV (Linux native) (push)", "CI / Cargo Audit + Deny (push)"]


def statuses(**states):
    names = dict(zip(("ok", "msrv", "audit"), REQUIRED))
    return [{"context": names[k], "status": v} for k, v in states.items()]


class EvaluateTests(unittest.TestCase):
    def test_all_success_passes(self):
        verdict, _ = gate.evaluate(statuses(ok="success", msrv="success", audit="success"), REQUIRED)
        self.assertEqual(verdict, "pass")

    def test_pending_or_missing_waits(self):
        self.assertEqual(gate.evaluate(statuses(ok="pending", msrv="success", audit="success"), REQUIRED)[0], "wait")
        verdict, states = gate.evaluate(statuses(ok="success"), REQUIRED)
        self.assertEqual(verdict, "wait")
        self.assertEqual(states["CI / MSRV (Linux native) (push)"], "missing")

    def test_skipped_heavy_job_waits(self):
        # A dev push skips MSRV and audit under the same context names; the
        # tag's run, which runs them, may not have reported yet.
        verdict, states = gate.evaluate(statuses(ok="success", msrv="skipped", audit="skipped"), REQUIRED)
        self.assertEqual(verdict, "wait")
        self.assertEqual(states["CI / MSRV (Linux native) (push)"], "skipped")

    def test_failure_or_error_fails_even_while_others_are_pending_or_skipped(self):
        for bad in ("failure", "error", "warning"):
            with self.subTest(bad=bad):
                self.assertEqual(gate.evaluate(statuses(ok="pending", msrv=bad), REQUIRED)[0], "fail")
                self.assertEqual(gate.evaluate(statuses(ok=bad, msrv="skipped", audit="skipped"), REQUIRED)[0],
                                 "fail")

    def test_other_contexts_dont_matter(self):
        extra = [{"context": "Release / Validate (push)", "status": "pending"}]
        verdict, _ = gate.evaluate(statuses(ok="success", msrv="success", audit="success") + extra, REQUIRED)
        self.assertEqual(verdict, "pass")


class FakeHttp:
    def __init__(self, pages):
        self.pages = list(pages)
        self.urls = []

    def call(self, method, url):
        self.urls.append(url)
        return self.pages.pop(0)


class MainTests(unittest.TestCase):
    ENV = {"GITHUB_SERVER_URL": "https://forgejo.invalid", "GITHUB_REPOSITORY": "o/r", "FORGEJO_TOKEN": "t"}

    def run_gate(self, responses, *args):
        fake = FakeHttp(responses)
        out, err = io.StringIO(), io.StringIO()
        argv = ["--commit", "abc", *[f"--context={c}" for c in REQUIRED], *args]
        with mock.patch.dict(os.environ, self.ENV), mock.patch.object(gate, "Http", lambda *a: fake), \
                mock.patch.object(gate, "POLL", 0), contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            code = gate.main(argv)
        return code, out.getvalue(), err.getvalue(), fake

    def combined(self, **states):
        found = statuses(**states)
        return {"statuses": found, "total_count": len(found)}

    def test_waits_for_pending_then_passes(self):
        code, out, _, fake = self.run_gate(
            [self.combined(ok="pending"), self.combined(ok="success", msrv="success", audit="success")],
            "--wait", "60")
        self.assertEqual(code, 0)
        self.assertIn("CI passed on abc", out)
        self.assertEqual(len(fake.urls), 2)
        self.assertIn("/repos/o/r/commits/abc/status?limit=50&page=1", fake.urls[0])

    def test_times_out(self):
        code, _, err, _ = self.run_gate([self.combined(ok="pending")], "--wait", "0")
        self.assertEqual(code, 1)
        self.assertIn("CI hasn't passed on abc after 0 s", err)

    def test_skipped_waits_for_the_tags_run(self):
        code, out, _, fake = self.run_gate(
            [self.combined(ok="success", msrv="skipped", audit="skipped"),
             self.combined(ok="success", msrv="pending", audit="skipped"),
             self.combined(ok="success", msrv="success", audit="success")],
            "--wait", "3600")
        self.assertEqual((code, len(fake.urls)), (0, 3))
        self.assertIn("CI passed on abc", out)

    def test_skipped_until_the_deadline_fails_without_suggesting_a_new_tag(self):
        code, _, err, _ = self.run_gate([self.combined(ok="success", msrv="skipped", audit="success")],
                                        "--wait", "0")
        self.assertEqual(code, 1)
        self.assertIn("MSRV (Linux native) (push): skipped", err)
        self.assertIn("Re-run the release once the tag's CI run has passed", err)
        self.assertNotIn("tag again", err)

    def test_failure_fails_at_once_and_explains(self):
        code, _, err, fake = self.run_gate([self.combined(ok="failure", msrv="skipped", audit="skipped")],
                                           "--wait", "3600")
        self.assertEqual((code, len(fake.urls)), (1, 1))
        self.assertIn("CI failed on abc", err)
        self.assertIn("re-run the failed CI jobs on this commit", err)

    def test_dry_run_only_warns(self):
        code, out, _, _ = self.run_gate([self.combined(ok="failure")], "--warn-only")
        self.assertEqual(code, 0)
        self.assertIn("::warning::", out)

    def test_pages_are_followed_until_a_short_page(self):
        # This Forgejo's total_count is the size of the page, not of the list.
        others = [{"context": f"CI / Job {i} (push)", "status": "success"} for i in range(gate.LIMIT - 1)]
        first = {"statuses": statuses(ok="success") + others, "total_count": gate.LIMIT}
        second = {"statuses": statuses(msrv="success", audit="success"), "total_count": 2}
        code, _, _, fake = self.run_gate([first, second])
        self.assertEqual((code, len(fake.urls)), (0, 2))
        self.assertIn("page=2", fake.urls[1])

    def test_a_full_last_page_ends_at_the_empty_one(self):
        full = statuses(ok="success", msrv="success", audit="success")
        full += [{"context": f"CI / Job {i} (push)", "status": "success"} for i in range(gate.LIMIT - 3)]
        code, _, _, fake = self.run_gate([{"statuses": full, "total_count": gate.LIMIT},
                                          {"statuses": [], "total_count": 0}])
        self.assertEqual((code, len(fake.urls)), (0, 2))

    def test_a_short_first_page_is_the_only_one(self):
        code, _, _, fake = self.run_gate([self.combined(ok="success", msrv="success", audit="success")])
        self.assertEqual((code, len(fake.urls)), (0, 1))


if __name__ == "__main__":
    unittest.main()
