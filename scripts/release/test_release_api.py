#!/usr/bin/env python3
"""Unit tests for release_api.py (no network): python3 -m unittest discover -s scripts/release"""

import contextlib
import copy
import io
import os
import tempfile
import unittest
import urllib.error
import urllib.request
from pathlib import Path
from unittest import mock

import release_api as api

api.RETRY_DELAY = 0


class SumsTests(unittest.TestCase):
    def test_round_trip(self):
        text = api.sums_text({"b.tar.gz": "bb", "a.whl": "aa"})
        self.assertEqual(text, "aa  a.whl\nbb  b.tar.gz\n")
        self.assertEqual(api.parse_sums(text), {"a.whl": "aa", "b.tar.gz": "bb"})
        self.assertEqual(api.parse_sums("cc *bin.exe\n\n"), {"bin.exe": "cc"})


class PickReleaseTests(unittest.TestCase):
    def test_published_wins_over_a_stray_draft(self):
        releases = [{"id": 2, "tag_name": "v1", "draft": True}, {"id": 1, "tag_name": "v1", "draft": False},
                    {"id": 3, "tag_name": "v2", "draft": False}]
        with contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(api.pick_release(releases, "v1")["id"], 1)

    def test_single_draft_and_none(self):
        self.assertEqual(api.pick_release([{"id": 5, "tag_name": "v1", "draft": True}], "v1")["id"], 5)
        self.assertIsNone(api.pick_release([{"id": 5, "tag_name": "v0", "draft": True}], "v1"))

    def test_two_drafts_are_ambiguous(self):
        drafts = [{"id": 5, "tag_name": "v1", "draft": True}, {"id": 6, "tag_name": "v1", "draft": True}]
        with self.assertRaisesRegex(api.ReleaseError, "several draft releases"):
            api.pick_release(drafts, "v1")


class Immutable(AssertionError):
    """A write to a published release, which GitHub refuses."""


class FakeHost:
    """Stands in for Forgejo or GitHub. Holds releases in memory, records every
    call, and, like GitHub, refuses any asset change once a release is public."""

    label = "Fake"
    published_hint = "Fake releases are immutable."

    def __init__(self, can_read_assets=True):
        self.can_read_assets = can_read_assets
        self.releases = []
        self.calls = []
        self.fail = {}  # asset name -> "lost" (stored, response lost) or "refused" (not stored)
        self.create_lost = False
        self.ids = iter(range(100, 10_000))

    def add(self, tag, files, draft):
        release = {"id": next(self.ids), "tag_name": tag, "draft": draft, "assets": []}
        self.releases.append(release)
        for name, data in files.items():
            self._store(release, name, data)
        return release

    def _store(self, release, name, data):
        release["assets"].append({"id": next(self.ids), "name": name, "size": len(data),
                                  "digest": "sha256:" + api.sha256_bytes(data), "data": data})

    def _live(self, release):
        return next(r for r in self.releases if r["id"] == release["id"])

    def _writable(self, release):
        live = self._live(release)
        if not live["draft"]:
            raise Immutable(f"release {live['tag_name']} is published")
        return live

    def find_release(self, tag):
        return api.pick_release(copy.deepcopy(self.releases), tag)

    def refresh(self, release):
        return copy.deepcopy(self._live(release))

    def create_draft(self, tag, name, notes, commit, prerelease):
        self.calls.append(("create", tag, name, commit, prerelease))
        release = self.add(tag, {}, draft=True)
        if self.create_lost:
            self.create_lost = False
            raise api.HttpFailure("POST /releases returned HTTP 502", 502)
        return copy.deepcopy(release)

    def assets(self, release):
        return {a["name"]: a for a in release["assets"]}

    def drop_incomplete(self, release):
        return []

    def upload(self, release, path):
        live = self._writable(release)
        self.calls.append(("upload", path.name))
        mode = self.fail.pop(path.name, None)
        if mode == "refused":
            raise api.HttpFailure("upload returned HTTP 502", 502)
        self._store(live, path.name, path.read_bytes())
        if mode == "lost":
            raise api.HttpFailure("upload failed: timed out")

    def delete_asset(self, release, item):
        live = self._writable(release)
        self.calls.append(("delete", item["name"]))
        live["assets"] = [a for a in live["assets"] if a["id"] != item["id"]]

    def download(self, release, item):
        if not self.can_read_assets:
            raise AssertionError("this host can't download")
        self.calls.append(("download", item["name"]))
        return item["data"]

    def asset_digest(self, release, item):
        if not self.can_read_assets:
            raise AssertionError("this host can't checksum")
        self.calls.append(("digest", item["name"]))
        return item["digest"].removeprefix("sha256:")

    def publish_release(self, release):
        self.calls.append(("publish",))
        self._live(release)["draft"] = False
        return copy.deepcopy(self._live(release))

    def files(self, tag="v1.0.0"):
        release = next(r for r in self.releases if r["tag_name"] == tag)
        return {a["name"]: a["data"] for a in release["assets"]}


WHEEL, BINARY = b"wheel", b"binary"
SUMS_OK = api.sums_text({"bacnet-linux-amd64": api.sha256_bytes(BINARY), "x.whl": api.sha256_bytes(WHEEL)}).encode()


class PublishTests(unittest.TestCase):
    COMMIT = "c0ffee"

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.dir = Path(self.tmp.name)
        (self.dir / "x.whl").write_bytes(WHEEL)
        (self.dir / "bacnet-linux-amd64").write_bytes(BINARY)

    def tearDown(self):
        self.tmp.cleanup()

    def run_publish(self, host, dry_run=False, tag="v1.0.0"):
        with contextlib.redirect_stdout(io.StringIO()) as out:
            api.publish(host, tag, "notes", self.dir, self.COMMIT, dry_run)
        return out.getvalue()

    def writes(self, host):
        return [c for c in host.calls if c[0] in ("create", "upload", "delete", "publish")]

    def test_new_release_stays_a_draft_until_everything_is_up(self):
        host = FakeHost()
        self.run_publish(host, tag="v1.0.0-rc.1")
        self.assertEqual(self.writes(host), [
            ("create", "v1.0.0-rc.1", "Rusty BACnet v1.0.0-rc.1", self.COMMIT, True),
            ("upload", "bacnet-linux-amd64"), ("upload", "x.whl"), ("upload", "SHA256SUMS"), ("publish",)])
        self.assertEqual(host.files("v1.0.0-rc.1")["SHA256SUMS"], SUMS_OK)
        self.assertFalse(host.releases[0]["draft"])

    def test_dry_run_without_a_release_writes_nothing(self):
        host = FakeHost()
        out = self.run_publish(host, dry_run=True)
        self.assertEqual(host.calls, [])
        self.assertIn(f"would create draft release v1.0.0 at {self.COMMIT}", out)
        self.assertIn("would upload x.whl", out)
        self.assertIn("would upload SHA256SUMS for 2 assets, then publish the draft", out)

    def test_dry_run_on_a_draft_writes_nothing_and_checks_downloads(self):
        host = FakeHost()
        host.add("v1.0.0", {"x.whl": WHEEL, "big.tar.gz": b"x" * 100}, draft=True)
        out = self.run_publish(host, dry_run=True)
        self.assertEqual(self.writes(host), [])
        self.assertIn("would resume draft release v1.0.0", out)
        self.assertIn("skip x.whl: already on the draft", out)
        self.assertIn("would upload bacnet-linux-amd64", out)
        self.assertIn("would upload SHA256SUMS for 3 assets", out)
        self.assertIn("download check: x.whl (5 bytes)", out)

    def test_resumed_draft_keeps_an_earlier_build(self):
        # A first run uploaded an x.whl that differs from this run's, then failed
        # before SHA256SUMS: the draft keeps its copy, and SHA256SUMS lists it.
        host = FakeHost()
        host.add("v1.0.0", {"x.whl": b"older wheel"}, draft=True)
        out = self.run_publish(host)
        self.assertEqual(self.writes(host), [("upload", "bacnet-linux-amd64"), ("upload", "SHA256SUMS"), ("publish",)])
        sums = api.parse_sums(host.files()["SHA256SUMS"].decode())
        self.assertEqual(sums["x.whl"], api.sha256_bytes(b"older wheel"))
        self.assertIn("x.whl is from an earlier build", out)
        self.assertNotIn(("download", "x.whl"), host.calls)  # the reported digest is enough

    def test_resumed_draft_replaces_a_stale_sums(self):
        host = FakeHost()
        host.add("v1.0.0", {"x.whl": WHEEL, "SHA256SUMS": b"00  x.whl\n"}, draft=True)
        self.run_publish(host)
        self.assertEqual(self.writes(host), [
            ("upload", "bacnet-linux-amd64"), ("delete", "SHA256SUMS"), ("upload", "SHA256SUMS"), ("publish",)])
        self.assertEqual(host.files()["SHA256SUMS"], SUMS_OK)

    def test_complete_draft_is_only_published(self):
        host = FakeHost()
        host.add("v1.0.0", {"x.whl": WHEEL, "bacnet-linux-amd64": BINARY, "SHA256SUMS": SUMS_OK}, draft=True)
        out = self.run_publish(host)
        self.assertEqual(self.writes(host), [("publish",)])
        self.assertIn("skip SHA256SUMS: up to date", out)

    def test_host_that_cant_read_assets_replaces_the_drafts_copies(self):
        host = FakeHost(can_read_assets=False)
        host.add("v1.0.0", {"x.whl": b"older wheel", "SHA256SUMS": b"00  x.whl\n"}, draft=True)
        self.run_publish(host)
        self.assertEqual(self.writes(host), [
            ("delete", "SHA256SUMS"), ("delete", "x.whl"), ("upload", "bacnet-linux-amd64"),
            ("upload", "x.whl"), ("upload", "SHA256SUMS"), ("publish",)])
        self.assertEqual(host.files()["SHA256SUMS"], SUMS_OK)

    def test_complete_published_release_is_left_alone(self):
        host = FakeHost()
        host.add("v1.0.0", {"x.whl": WHEEL, "bacnet-linux-amd64": BINARY, "SHA256SUMS": SUMS_OK}, draft=False)
        out = self.run_publish(host)
        self.assertEqual(self.writes(host), [])
        self.assertIn("is complete; nothing to do", out)

    def test_incomplete_published_release_fails_without_writing(self):
        host = FakeHost()
        host.add("v1.0.0", {"x.whl": WHEEL}, draft=False)
        with self.assertRaises(api.ReleaseError) as caught, contextlib.redirect_stdout(io.StringIO()):
            api.publish(host, "v1.0.0", "notes", self.dir, self.COMMIT, False)
        self.assertEqual(self.writes(host), [])
        message = str(caught.exception)
        for want in ("published but incomplete", "bacnet-linux-amd64 is missing", "SHA256SUMS is missing",
                     "immutable"):
            self.assertIn(want, message)

    def test_incomplete_published_release_only_warns_on_a_dry_run(self):
        host = FakeHost()
        host.add("v1.0.0", {"x.whl": WHEEL}, draft=False)
        out = self.run_publish(host, dry_run=True)
        self.assertEqual(self.writes(host), [])
        self.assertIn("::warning::Fake release v1.0.0 is published but incomplete", out)
        self.assertIn("A real run would stop here.", out)

    def test_published_asset_that_doesnt_match_sums_is_a_problem(self):
        host = FakeHost()
        sums = api.sums_text({"bacnet-linux-amd64": api.sha256_bytes(BINARY), "x.whl": "00"}).encode()
        host.add("v1.0.0", {"x.whl": WHEEL, "bacnet-linux-amd64": BINARY, "SHA256SUMS": sums}, draft=False)
        with self.assertRaisesRegex(api.ReleaseError, "x.whl doesn't match its SHA256SUMS entry"), \
                contextlib.redirect_stdout(io.StringIO()):
            api.publish(host, "v1.0.0", "notes", self.dir, self.COMMIT, False)

    def test_fake_host_refuses_uploads_after_publishing(self):
        # Publishing before the uploads would fail here, as it would on GitHub.
        host = FakeHost()
        release = host.add("v1.0.0", {}, draft=True)
        host.publish_release(release)
        with self.assertRaises(Immutable):
            host.upload(release, self.dir / "x.whl")
        with self.assertRaises(Immutable):
            host.delete_asset(release, {"id": 0, "name": "x.whl"})

    def test_lost_upload_response_is_not_sent_again(self):
        host = FakeHost()
        host.fail["x.whl"] = "lost"
        out = self.run_publish(host)
        self.assertEqual([c for c in host.calls if c == ("upload", "x.whl")], [("upload", "x.whl")])
        self.assertIn("x.whl arrived after all", out)
        self.assertEqual(host.files()["SHA256SUMS"], SUMS_OK)

    def test_refused_upload_is_sent_again(self):
        host = FakeHost()
        host.fail["x.whl"] = "refused"
        self.run_publish(host)
        self.assertEqual([c for c in host.calls if c == ("upload", "x.whl")], [("upload", "x.whl")] * 2)
        self.assertEqual(host.files()["SHA256SUMS"], SUMS_OK)

    def test_lost_create_response_reuses_the_draft(self):
        host = FakeHost()
        host.create_lost = True
        self.run_publish(host)
        self.assertEqual(len(host.releases), 1)
        self.assertEqual([c[0] for c in self.writes(host)].count("create"), 1)
        self.assertFalse(host.releases[0]["draft"])


class HttpTests(unittest.TestCase):
    def test_token_is_never_redirected(self):
        http = api.Http("Bearer secret-value", {"Accept": "application/json"})
        req = http.build("GET", "https://api.github.com/repos/o/r/releases/assets/1",
                         accept="application/octet-stream")
        self.assertNotIn("Authorization", req.headers)
        self.assertEqual(req.unredirected_hdrs["Authorization"], "Bearer secret-value")
        self.assertEqual(req.get_header("Accept"), "application/octet-stream")
        moved = urllib.request.HTTPRedirectHandler().redirect_request(
            req, None, 302, "Found", {}, "https://release-assets.githubusercontent.com/x?sig=1")
        self.assertIsNone(moved.get_header("Authorization"))
        self.assertEqual(moved.get_header("Accept"), "application/octet-stream")

    def fake_urlopen(self, codes):
        calls = []

        def urlopen(req, timeout):
            calls.append(req.get_method())
            raise urllib.error.HTTPError(req.full_url, codes.pop(0), "error", {}, io.BytesIO(b"oops"))

        return urlopen, calls

    def test_post_is_not_retried_but_get_is(self):
        http = api.Http("token t")
        urlopen, calls = self.fake_urlopen([502] * 5)
        with mock.patch.object(urllib.request, "urlopen", urlopen):
            with self.assertRaises(api.HttpFailure) as caught:
                http.call("POST", "https://h.invalid/x", b"data", retry=False)
            self.assertTrue(caught.exception.uncertain)
            self.assertEqual(calls, ["POST"])
            with self.assertRaises(api.HttpFailure):
                http.call("GET", "https://h.invalid/x")
        self.assertEqual(calls, ["POST"] + ["GET"] * 4)

    def test_client_errors_are_not_retried(self):
        http = api.Http("token t")
        urlopen, calls = self.fake_urlopen([422])
        with mock.patch.object(urllib.request, "urlopen", urlopen):
            with self.assertRaisesRegex(api.HttpFailure, "HTTP 422: oops") as caught:
                http.call("GET", "https://h.invalid/x")
        self.assertFalse(caught.exception.uncertain)
        self.assertEqual(calls, ["GET"])

    def test_github_downloads_draft_assets_through_the_api(self):
        host = api.GitHub("o/r", "t")
        seen = []

        def call(method, url, **kwargs):
            seen.append((method, url, kwargs))
            return b"12345"

        item = {"name": "x.whl", "size": 5, "url": "https://api.github.com/repos/o/r/releases/assets/7",
                "browser_download_url": "https://github.com/o/r/releases/download/v1/x.whl"}
        with mock.patch.object(host.http, "call", call):
            self.assertEqual(host.download({}, item), b"12345")
            with self.assertRaisesRegex(api.ReleaseError, "gave 5 bytes, expected 6"):
                host.download({}, {**item, "size": 6})
        self.assertEqual(seen[0], ("GET", item["url"], {"accept": "application/octet-stream", "raw": True}))

    def test_github_digest_comes_from_the_asset_when_reported(self):
        host = api.GitHub("o/r", "t")
        self.assertEqual(host.asset_digest({}, {"digest": "sha256:abc"}), "abc")


class FakeTags:
    def __init__(self, commit):
        self.commit = commit

    def tag_commit(self, tag):
        return self.commit


class CheckTagTests(unittest.TestCase):
    def test_tag_elsewhere_fails_a_real_run_and_warns_a_dry_run(self):
        with self.assertRaisesRegex(api.ReleaseError, "points at bbb, not aaa"):
            api.check_tag(FakeTags("bbb"), "v1", "aaa", 0, dry_run=False)
        with contextlib.redirect_stdout(io.StringIO()) as out:
            api.check_tag(FakeTags("bbb"), "v1", "aaa", 0, dry_run=True)
        self.assertIn("::warning::GitHub's v1 points at bbb", out.getvalue())

    def test_missing_tag_doesnt_wait_on_a_dry_run(self):
        with contextlib.redirect_stdout(io.StringIO()) as out:
            api.check_tag(FakeTags(None), "v1", "aaa", 900, dry_run=True)
        self.assertIn("a real run would wait 900 s", out.getvalue())
        with self.assertRaisesRegex(api.ReleaseError, "no tag v1 after 0 s"), \
                contextlib.redirect_stdout(io.StringIO()):
            api.check_tag(FakeTags(None), "v1", "aaa", 0, dry_run=False)


class GitHubTokenTests(unittest.TestCase):
    def test_missing_token_fails_clearly(self):
        env = {k: v for k, v in os.environ.items() if k != "GH_RELEASE_TOKEN"}
        with tempfile.TemporaryDirectory() as tmp, mock.patch.dict(os.environ, env, clear=True):
            Path(tmp, "notes.md").write_text("n")
            err = io.StringIO()
            with contextlib.redirect_stderr(err):
                code = api.main(["github", "--tag", "v1.0.0", "--notes", str(Path(tmp, "notes.md")),
                                 "--assets", tmp, "--commit", "abc"])
        self.assertEqual(code, 1)
        self.assertIn("GH_RELEASE_TOKEN is not set", err.getvalue())
        self.assertIn("Contents read and write", err.getvalue())


if __name__ == "__main__":
    unittest.main()
