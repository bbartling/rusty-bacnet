#!/usr/bin/env python3
"""Unit tests for release_api.py (no network): python3 -m unittest discover -s scripts/release"""

import contextlib
import io
import os
import tempfile
import unittest
from pathlib import Path
from unittest import mock

import release_api as api


class SumsTests(unittest.TestCase):
    def test_round_trip(self):
        text = api.sums_text({"b.tar.gz": "bb", "a.whl": "aa"})
        self.assertEqual(text, "aa  a.whl\nbb  b.tar.gz\n")
        self.assertEqual(api.parse_sums(text), {"a.whl": "aa", "b.tar.gz": "bb"})
        self.assertEqual(api.parse_sums("cc *bin.exe\n\n"), {"bin.exe": "cc"})


class ReleaseDigestsTests(unittest.TestCase):
    LOCAL = {"a.whl": "aa", "b.tar.gz": "bb"}

    def remote(self, digests):
        calls = []

        def digest(name):
            calls.append(name)
            return digests[name]

        return digest, calls

    def test_new_assets_use_local_digests(self):
        digest, calls = self.remote({})
        self.assertEqual(api.release_digests(self.LOCAL, {"a.whl", "b.tar.gz"}, None, digest), (self.LOCAL, []))
        self.assertEqual(calls, [])

    def test_existing_assets_keep_the_release_copy(self):
        digest, calls = self.remote({"a.whl": "old"})
        digests, differs = api.release_digests(self.LOCAL, {"b.tar.gz"}, None, digest)
        self.assertEqual((digests, differs, calls), ({"a.whl": "old", "b.tar.gz": "bb"}, ["a.whl"], ["a.whl"]))

    def test_matching_published_sums_avoid_downloads(self):
        digest, calls = self.remote({})
        digests, differs = api.release_digests(self.LOCAL, set(), {"a.whl": "aa", "b.tar.gz": "bb"}, digest)
        self.assertEqual((digests, differs, calls), (self.LOCAL, [], []))

    def test_other_published_digest_is_checked_against_the_asset(self):
        digest, calls = self.remote({"a.whl": "old"})
        digests, differs = api.release_digests(self.LOCAL, {"b.tar.gz"}, {"a.whl": "stale"}, digest)
        self.assertEqual((digests, differs, calls), ({"a.whl": "old", "b.tar.gz": "bb"}, ["a.whl"], ["a.whl"]))


class FakeHost:
    """Stands in for Forgejo or GitHub: holds assets in memory and records writes."""

    def __init__(self, assets=None):
        self.release = None if assets is None else {"id": 1, "assets": [{"name": n} for n in assets]}
        self.files = dict(assets or {})
        self.calls = []

    def get_release(self, tag):
        return self.release

    def create_release(self, tag, name, notes, prerelease):
        self.calls.append(("create", tag, name, prerelease))
        self.release = {"id": 1, "assets": []}
        return self.release

    def assets(self, release):
        return {a["name"]: len(self.files[a["name"]]) for a in release["assets"]}

    def drop_incomplete(self, release):
        pass

    def download(self, release, name):
        self.calls.append(("download", name))
        return self.files[name]

    def upload(self, release, path):
        self.calls.append(("upload", path.name))
        self.files[path.name] = path.read_bytes()
        self.release["assets"].append({"name": path.name})

    def delete(self, release, name):
        self.calls.append(("delete", name))
        del self.files[name]
        self.release["assets"] = [a for a in self.release["assets"] if a["name"] != name]


class PublishTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.dir = Path(self.tmp.name)
        (self.dir / "x.whl").write_bytes(b"wheel")
        (self.dir / "bacnet-linux-amd64").write_bytes(b"binary")

    def tearDown(self):
        self.tmp.cleanup()

    def run_publish(self, host, dry_run=False, tag="v1.0.0"):
        with contextlib.redirect_stdout(io.StringIO()) as out:
            api.publish(host, tag, "notes", self.dir, dry_run)
        return out.getvalue()

    def writes(self, host):
        return [c for c in host.calls if c[0] != "download"]

    def test_creates_release_and_uploads_sums_last(self):
        host = FakeHost()
        self.run_publish(host, tag="v1.0.0-rc.1")
        self.assertEqual(self.writes(host), [
            ("create", "v1.0.0-rc.1", "Rusty BACnet v1.0.0-rc.1", True),
            ("upload", "bacnet-linux-amd64"), ("upload", "x.whl"), ("upload", "SHA256SUMS")])
        sums = api.parse_sums(host.files["SHA256SUMS"].decode())
        self.assertEqual(sums, {"x.whl": api.sha256_bytes(b"wheel"), "bacnet-linux-amd64": api.sha256_bytes(b"binary")})

    def test_dry_run_writes_nothing(self):
        host = FakeHost()
        out = self.run_publish(host, dry_run=True)
        self.assertEqual(host.calls, [])
        self.assertIn("would create release v1.0.0", out)
        self.assertIn("would upload x.whl", out)
        self.assertIn("would upload SHA256SUMS", out)

    def test_complete_release_is_left_alone(self):
        host = FakeHost()
        self.run_publish(host)
        host.calls.clear()
        out = self.run_publish(host)
        self.assertEqual(self.writes(host), [])
        self.assertEqual(host.calls, [("download", "SHA256SUMS")])
        self.assertIn("skip SHA256SUMS: up to date", out)

    def test_partial_release_from_another_build(self):
        # A first run uploaded an x.whl that differs from this run's, then failed
        # before SHA256SUMS: the release keeps its copy, and SHA256SUMS lists it.
        host = FakeHost({"x.whl": b"older wheel"})
        out = self.run_publish(host)
        self.assertEqual(self.writes(host), [("upload", "bacnet-linux-amd64"), ("upload", "SHA256SUMS")])
        sums = api.parse_sums(host.files["SHA256SUMS"].decode())
        self.assertEqual(sums["x.whl"], api.sha256_bytes(b"older wheel"))
        self.assertIn("x.whl is from an earlier build", out)

    def test_stale_sums_is_replaced(self):
        host = FakeHost({"x.whl": b"wheel", "SHA256SUMS": b"00  x.whl\n"})
        self.run_publish(host)
        self.assertEqual(self.writes(host), [
            ("upload", "bacnet-linux-amd64"), ("delete", "SHA256SUMS"), ("upload", "SHA256SUMS")])
        self.assertIn(("download", "x.whl"), host.calls)
        sums = api.parse_sums(host.files["SHA256SUMS"].decode())
        self.assertEqual(sums["x.whl"], api.sha256_bytes(b"wheel"))


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
