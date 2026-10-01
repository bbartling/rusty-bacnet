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
from http.client import IncompleteRead
from pathlib import Path
from unittest import mock

import release_api as api

api.RETRY_DELAY = 0
COMMIT = "c0ffee"


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
    """Stands in for Forgejo or GitHub. Holds releases and tags in memory,
    records every call, and, like GitHub, refuses any asset change once a
    release is public. can_read_assets=False is Forgejo-like: no digests, no
    downloads."""

    label = "Fake"
    published_hint = "Fake releases are immutable."

    def __init__(self, can_read_assets=True, draft_creates_tag=False, hide_drafts=False):
        self.can_read_assets = can_read_assets
        self.draft_creates_tag = draft_creates_tag
        self.hide_drafts = hide_drafts
        self.releases = []
        self.tags = set()
        self.calls = []
        # asset name -> how its next upload goes wrong:
        #   lost      stored, response lost
        #   refused   not stored, HTTP 502
        #   forbidden not stored, HTTP 400 (a type the host doesn't allow)
        #   exists    stored, then HTTP 422 already_exists (as after a lost response)
        #   corrupt   other bytes stored, success
        #   dup       stored twice, success
        #   stray     stored, plus an incomplete upload of another file
        self.fail = {}
        self.create_lost = False
        self.fail_delete_release = False
        self.ids = iter(range(100, 10_000))

    def add(self, tag, files, draft, commit=COMMIT):
        release = {"id": next(self.ids), "tag_name": tag, "draft": draft, "target_commitish": commit,
                   "assets": []}
        self.releases.append(release)
        for name, data in files.items():
            self._store(release, name, data)
        return release

    def _store(self, release, name, data, state="uploaded"):
        item = {"id": next(self.ids), "name": name, "size": len(data), "state": state, "data": data}
        if self.can_read_assets:
            item["digest"] = "sha256:" + api.sha256_bytes(data)
        release["assets"].append(item)

    def _live(self, release):
        return next(r for r in self.releases if r["id"] == release["id"])

    def _writable(self, release):
        live = self._live(release)
        if not live["draft"]:
            raise Immutable(f"release {live['tag_name']} is published")
        return live

    def list_releases(self):
        return [copy.deepcopy(r) for r in self.releases if not (self.hide_drafts and r["draft"])]

    def find_release(self, tag):
        return api.pick_release(self.list_releases(), tag)

    def refresh(self, release):
        return copy.deepcopy(self._live(release))

    def exists(self, release):
        return any(r["id"] == release["id"] for r in self.releases)

    def create_draft(self, tag, name, notes, commit, prerelease):
        self.calls.append(("create", tag, name, commit, prerelease))
        release = self.add(tag, {}, draft=True, commit=commit)
        if self.draft_creates_tag:
            self.tags.add(tag)
        if self.create_lost:
            self.create_lost = False
            raise api.HttpFailure("POST /releases returned HTTP 502", 502)
        return copy.deepcopy(release)

    def raw_assets(self, release):
        return release["assets"]

    def assets(self, release):
        return {a["name"]: a for a in release["assets"] if a["state"] == "uploaded"}

    def drop_incomplete(self, release):
        live = self._writable(release)
        dropped = [a["name"] for a in live["assets"] if a["state"] != "uploaded"]
        for name in dropped:
            self.calls.append(("delete", name))
        live["assets"] = [a for a in live["assets"] if a["state"] == "uploaded"]
        return dropped

    def upload(self, release, path):
        live = self._writable(release)
        self.calls.append(("upload", path.name))
        mode = self.fail.pop(path.name, None)
        if mode == "refused":
            raise api.HttpFailure("upload returned HTTP 502", 502)
        if mode == "forbidden":
            raise api.HttpFailure("upload returned HTTP 400: type not allowed", 400)
        data = path.read_bytes()
        self._store(live, path.name, data + b"!" if mode == "corrupt" else data)
        if mode == "dup":
            self._store(live, path.name, data)
        if mode == "stray":
            self._store(live, "late.bin", b"", state="starter")
        if mode == "lost":
            raise api.HttpFailure("upload failed: timed out")
        if mode == "exists":
            detail = '{"message":"Validation Failed","errors":[{"resource":"ReleaseAsset","code":"already_exists"}]}'
            raise api.HttpFailure(f"upload returned HTTP 422: {detail}", 422, detail)

    def delete_asset(self, release, item):
        live = self._writable(release)
        self.calls.append(("delete", item["name"]))
        live["assets"] = [a for a in live["assets"] if a["id"] != item["id"]]

    def delete_release(self, release):
        self.calls.append(("delete-release", release["tag_name"]))
        if self.fail_delete_release:
            raise api.HttpFailure("DELETE /releases returned HTTP 403: forbidden", 403)
        self.releases = [r for r in self.releases if r["id"] != release["id"]]

    def tag_exists(self, tag):
        return tag in self.tags

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
        self.tags.add(release["tag_name"])
        return copy.deepcopy(self._live(release))

    def files(self, tag="v1.0.0"):
        release = next(r for r in self.releases if r["tag_name"] == tag)
        return {a["name"]: a["data"] for a in release["assets"]}


WRITES = ("create", "upload", "delete", "delete-release", "publish")


def writes(host):
    return [c for c in host.calls if c[0] in WRITES]


WHEEL, BINARY = b"wheel", b"binary"
SUMS_OK = api.sums_text({"bacnet-linux-amd64": api.sha256_bytes(BINARY), "x.whl": api.sha256_bytes(WHEEL)}).encode()


class PublishTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.dir = Path(self.tmp.name)
        (self.dir / "x.whl").write_bytes(WHEEL)
        (self.dir / "bacnet-linux-amd64").write_bytes(BINARY)

    def tearDown(self):
        self.tmp.cleanup()

    def run_publish(self, host, dry_run=False, tag="v1.0.0"):
        with contextlib.redirect_stdout(io.StringIO()) as out:
            api.publish(host, tag, "notes", self.dir, COMMIT, dry_run)
        return out.getvalue()

    def publish_fails(self, host, pattern):
        with self.assertRaisesRegex(api.ReleaseError, pattern) as caught, \
                contextlib.redirect_stdout(io.StringIO()):
            api.publish(host, "v1.0.0", "notes", self.dir, COMMIT, False)
        self.assertNotIn(("publish",), host.calls)
        return str(caught.exception)

    def test_new_release_stays_a_draft_until_everything_is_up(self):
        host = FakeHost()
        out = self.run_publish(host, tag="v1.0.0-rc.1")
        self.assertEqual(writes(host), [
            ("create", "v1.0.0-rc.1", "Rusty BACnet v1.0.0-rc.1", COMMIT, True),
            ("upload", "bacnet-linux-amd64"), ("upload", "x.whl"), ("upload", "SHA256SUMS"), ("publish",)])
        self.assertEqual(host.files("v1.0.0-rc.1")["SHA256SUMS"], SUMS_OK)
        self.assertFalse(host.releases[0]["draft"])
        self.assertIn("final check: 3 assets as expected (reported sha256 digest)", out)

    def test_dry_run_without_a_release_writes_nothing(self):
        host = FakeHost()
        out = self.run_publish(host, dry_run=True)
        self.assertEqual(host.calls, [])
        self.assertIn(f"would create draft release v1.0.0 at {COMMIT}", out)
        self.assertIn("would upload x.whl", out)
        self.assertIn("would upload SHA256SUMS for 2 assets, check them all, then publish the draft", out)

    def test_dry_run_on_a_draft_writes_nothing_and_checks_downloads(self):
        host = FakeHost()
        host.add("v1.0.0", {"x.whl": WHEEL, "big.tar.gz": b"x" * 100}, draft=True)
        out = self.run_publish(host, dry_run=True)
        self.assertEqual(writes(host), [])
        self.assertIn("would resume draft release v1.0.0", out)
        self.assertIn("skip x.whl: already on the draft", out)
        self.assertIn("would upload bacnet-linux-amd64", out)
        self.assertIn("would delete big.tar.gz: it isn't part of this release", out)
        self.assertIn("would upload SHA256SUMS for 2 assets", out)
        self.assertIn("download check: x.whl (5 bytes)", out)

    def test_dry_run_warns_about_a_draft_for_another_commit(self):
        host = FakeHost()
        host.add("v1.0.0", {"x.whl": WHEEL}, draft=True, commit="beef")
        out = self.run_publish(host, dry_run=True)
        self.assertEqual(writes(host), [])
        self.assertIn("::warning::Fake has a draft release v1.0.0", out)
        self.assertIn("A real run would stop here.", out)

    def test_resumed_draft_keeps_an_earlier_build(self):
        # A first run uploaded an x.whl that differs from this run's, then failed
        # before SHA256SUMS: the draft keeps its copy, and SHA256SUMS lists it.
        host = FakeHost()
        host.add("v1.0.0", {"x.whl": b"older wheel"}, draft=True)
        out = self.run_publish(host)
        self.assertEqual(writes(host), [("upload", "bacnet-linux-amd64"), ("upload", "SHA256SUMS"), ("publish",)])
        sums = api.parse_sums(host.files()["SHA256SUMS"].decode())
        self.assertEqual(sums["x.whl"], api.sha256_bytes(b"older wheel"))
        self.assertIn("x.whl is from an earlier build", out)
        self.assertNotIn(("download", "x.whl"), host.calls)  # the reported digest is enough

    def test_resumed_draft_replaces_a_stale_sums(self):
        host = FakeHost()
        host.add("v1.0.0", {"x.whl": WHEEL, "SHA256SUMS": b"00  x.whl\n"}, draft=True)
        self.run_publish(host)
        self.assertEqual(writes(host), [
            ("upload", "bacnet-linux-amd64"), ("delete", "SHA256SUMS"), ("upload", "SHA256SUMS"), ("publish",)])
        self.assertEqual(host.files()["SHA256SUMS"], SUMS_OK)

    def test_complete_draft_is_only_published(self):
        host = FakeHost()
        host.add("v1.0.0", {"x.whl": WHEEL, "bacnet-linux-amd64": BINARY, "SHA256SUMS": SUMS_OK}, draft=True)
        out = self.run_publish(host)
        self.assertEqual(writes(host), [("publish",)])
        self.assertIn("skip SHA256SUMS: up to date", out)

    def test_draft_for_another_commit_is_refused(self):
        host = FakeHost()
        host.add("v1.0.0", {"x.whl": WHEEL}, draft=True, commit="beef")
        message = self.publish_fails(host, "made for beef, not c0ffee")
        self.assertIn("Delete that draft", message)
        self.assertEqual(writes(host), [])

    def test_extra_assets_on_a_draft_are_deleted_and_not_published(self):
        host = FakeHost()
        host.add("v1.0.0", {"x.whl": WHEEL, "old-tool.exe": b"old", "SHA256SUMS": b"00  old-tool.exe\n"},
                 draft=True)
        self.run_publish(host)
        self.assertEqual(writes(host), [
            ("delete", "old-tool.exe"), ("upload", "bacnet-linux-amd64"), ("delete", "SHA256SUMS"),
            ("upload", "SHA256SUMS"), ("publish",)])
        self.assertEqual(set(host.files()), {"x.whl", "bacnet-linux-amd64", "SHA256SUMS"})
        self.assertEqual(host.files()["SHA256SUMS"], SUMS_OK)

    def test_host_that_cant_read_assets_replaces_the_drafts_copies(self):
        host = FakeHost(can_read_assets=False)
        host.add("v1.0.0", {"x.whl": b"older wheel", "SHA256SUMS": b"00  x.whl\n"}, draft=True)
        out = self.run_publish(host)
        self.assertEqual(writes(host), [
            ("delete", "SHA256SUMS"), ("delete", "x.whl"), ("upload", "bacnet-linux-amd64"),
            ("upload", "x.whl"), ("upload", "SHA256SUMS"), ("publish",)])
        self.assertEqual(host.files()["SHA256SUMS"], SUMS_OK)
        self.assertIn("size only: the host reports no digest", out)

    def test_duplicate_names_on_a_forgejo_draft_are_all_deleted(self):
        host = FakeHost(can_read_assets=False)
        release = host.add("v1.0.0", {"x.whl": WHEEL}, draft=True)
        host._store(release, "x.whl", b"other wheel")
        self.run_publish(host)
        self.assertEqual(writes(host)[:2], [("delete", "x.whl"), ("delete", "x.whl")])
        self.assertEqual([a["name"] for a in host.releases[0]["assets"]].count("x.whl"), 1)

    def test_duplicate_left_by_an_upload_stops_before_publishing(self):
        host = FakeHost(can_read_assets=False)
        host.fail["x.whl"] = "dup"
        self.assertIn("several assets are named x.whl", self.publish_fails(host, "failed the final check"))
        self.assertTrue(host.releases[0]["draft"])

    def test_corrupted_upload_stops_before_publishing(self):
        host = FakeHost()
        host.fail["x.whl"] = "corrupt"
        message = self.publish_fails(host, "failed the final check, so it stays a draft")
        self.assertIn("x.whl is 6 bytes, expected 5", message)
        self.assertTrue(host.releases[0]["draft"])

    def test_digest_mismatch_of_the_same_size_stops_before_publishing(self):
        host = FakeHost()
        release = host.add("v1.0.0", {}, draft=True)
        original = host.upload

        def upload(rel, path):
            original(rel, path)
            if path.name == "x.whl":  # same size, other bytes
                item = host._live(release)["assets"][-1]
                item["digest"] = "sha256:" + api.sha256_bytes(b"WHEEL")

        host.upload = upload
        message = self.publish_fails(host, "failed the final check")
        self.assertIn(f"x.whl has sha256 {api.sha256_bytes(b'WHEEL')}, expected {api.sha256_bytes(WHEEL)}",
                      message)

    def test_sums_digest_is_checked_too(self):
        host = FakeHost()
        host.fail["SHA256SUMS"] = "corrupt"
        self.assertIn("SHA256SUMS is", self.publish_fails(host, "failed the final check"))

    def test_incomplete_entry_stops_before_publishing(self):
        host = FakeHost()
        host.fail["SHA256SUMS"] = "stray"
        message = self.publish_fails(host, "failed the final check")
        self.assertIn("late.bin is not completely uploaded (state starter)", message)
        self.assertIn("late.bin isn't part of this release", message)

    def test_missing_digest_falls_back_to_downloading(self):
        host = FakeHost()
        host.add("v1.0.0", {"x.whl": WHEEL, "bacnet-linux-amd64": BINARY, "SHA256SUMS": SUMS_OK}, draft=True)
        for item in host.releases[0]["assets"]:
            del item["digest"]
        host.asset_digest = lambda release, item: api.sha256_bytes(host.download(release, item))
        out = self.run_publish(host)
        self.assertIn("(downloaded sha256)", out)
        self.assertEqual(writes(host), [("publish",)])

    def test_complete_published_release_is_left_alone(self):
        host = FakeHost()
        host.add("v1.0.0", {"x.whl": WHEEL, "bacnet-linux-amd64": BINARY, "SHA256SUMS": SUMS_OK}, draft=False)
        out = self.run_publish(host)
        self.assertEqual(writes(host), [])
        self.assertIn("is complete; nothing to do", out)

    def test_incomplete_published_release_fails_without_writing(self):
        host = FakeHost()
        host.add("v1.0.0", {"x.whl": WHEEL}, draft=False)
        message = self.publish_fails(host, "published but incomplete")
        self.assertEqual(writes(host), [])
        for want in ("bacnet-linux-amd64 is missing", "SHA256SUMS is missing", "immutable"):
            self.assertIn(want, message)

    def test_incomplete_published_release_only_warns_on_a_dry_run(self):
        host = FakeHost()
        host.add("v1.0.0", {"x.whl": WHEEL}, draft=False)
        out = self.run_publish(host, dry_run=True)
        self.assertEqual(writes(host), [])
        self.assertIn("::warning::Fake release v1.0.0 is published but incomplete", out)
        self.assertIn("A real run would stop here.", out)

    def test_published_asset_that_doesnt_match_sums_is_a_problem(self):
        host = FakeHost()
        sums = api.sums_text({"bacnet-linux-amd64": api.sha256_bytes(BINARY), "x.whl": "00"}).encode()
        host.add("v1.0.0", {"x.whl": WHEEL, "bacnet-linux-amd64": BINARY, "SHA256SUMS": sums}, draft=False)
        self.publish_fails(host, "x.whl doesn't match its SHA256SUMS entry")

    def test_published_release_with_duplicate_names_is_a_problem(self):
        host = FakeHost(can_read_assets=False)
        release = host.add("v1.0.0", {"x.whl": WHEEL, "bacnet-linux-amd64": BINARY, "SHA256SUMS": SUMS_OK},
                           draft=False)
        host._store(release, "x.whl", WHEEL)
        self.publish_fails(host, "several assets are named x.whl")

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

    def test_already_exists_with_the_same_bytes_is_accepted(self):
        host = FakeHost()
        host.fail["x.whl"] = "exists"
        out = self.run_publish(host)
        self.assertEqual([c for c in host.calls if c == ("upload", "x.whl")], [("upload", "x.whl")])
        self.assertIn("x.whl arrived after all", out)
        self.assertFalse(host.releases[0]["draft"])

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
        self.assertEqual([c[0] for c in writes(host)].count("create"), 1)
        self.assertFalse(host.releases[0]["draft"])


PROBE = "release-preflight-42-0a1b2c3d"


class FakeTags:
    def __init__(self, commit):
        self.commit = commit
        self.calls = 0

    def tag_commit(self, tag):
        self.calls += 1
        return self.commit


class PreflightTests(unittest.TestCase):
    def run_preflight(self, host, read_only=False, tags=None, tag="v1.0.0"):
        out, err = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            api.preflight(host, tag, COMMIT, PROBE, read_only, tags)
        return out.getvalue() + err.getvalue()

    def preflight_fails(self, host, pattern, **kwargs):
        err = io.StringIO()
        with self.assertRaisesRegex(api.ReleaseError, pattern) as caught, \
                contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(err):
            api.preflight(host, "v1.0.0", COMMIT, PROBE, False, **kwargs)
        return str(caught.exception), err.getvalue()

    def assert_cleaned_up(self, host):
        self.assertEqual([r for r in host.releases if r["tag_name"] == PROBE], [])
        self.assertNotIn(("publish",), host.calls)

    def test_write_check_drafts_uploads_checks_and_deletes(self):
        host = FakeHost()
        out = self.run_preflight(host, tags=FakeTags(COMMIT))
        uploads = [("upload", name) for name in sorted(api.PROBE_ASSETS)]
        self.assertEqual(writes(host), [("create", PROBE, f"Release preflight {PROBE}", COMMIT, True), *uploads,
                                        ("delete-release", PROBE)])
        self.assert_cleaned_up(host)
        self.assertEqual(host.tags, set())
        self.assertIn("GitHub has v1.0.0 at c0ffee", out)
        self.assertIn("Fake has no release v1.0.0 yet", out)
        self.assertIn("final check: 3 assets as expected", out)
        self.assertIn("download check: bacnet-linux-amd64 (1 bytes)", out)
        self.assertIn(f"write check: no release or tag {PROBE} is left", out)
        self.assertIn("Fake preflight passed", out)

    def test_write_check_on_a_forgejo_like_host_checks_sizes(self):
        host = FakeHost(can_read_assets=False)
        out = self.run_preflight(host)
        self.assert_cleaned_up(host)
        self.assertIn("size only", out)
        self.assertNotIn(("download", "bacnet-linux-amd64"), host.calls)

    def test_probe_assets_are_named_like_the_release_assets(self):
        names = sorted(api.PROBE_ASSETS)
        self.assertEqual([n for n in names if "." not in n], ["bacnet-linux-amd64"])
        self.assertTrue(any(n.endswith(".whl") for n in names))
        self.assertTrue(any(n.endswith(".tar.gz") for n in names))
        self.assertEqual(len(api.PROBE_ASSETS["bacnet-linux-amd64"]), 1)

    def test_read_only_makes_no_write(self):
        host = FakeHost()
        host.add("v1.0.0", {}, draft=False)
        out = self.run_preflight(host, read_only=True, tags=FakeTags(None))
        self.assertEqual(writes(host), [])
        self.assertIn("GitHub has no tag v1.0.0 yet", out)
        self.assertIn("already published; the publish job will only check it", out)
        self.assertIn("read only: the Fake write check runs only when publishing", out)

    def test_tag_elsewhere_stops_before_any_host_call(self):
        host = FakeHost()
        self.preflight_fails(host, "points at beef, not c0ffee", tags=FakeTags("beef"))
        self.assertEqual(host.calls, [])

    def test_draft_for_another_commit_stops_before_the_write_check(self):
        host = FakeHost()
        host.add("v1.0.0", {}, draft=True, commit="beef")
        self.preflight_fails(host, "made for beef, not c0ffee")
        self.assertEqual(writes(host), [])
        out = self.run_preflight(host, read_only=True)
        self.assertIn("::warning::Fake has a draft release v1.0.0", out)

    def test_resumable_draft_is_reported(self):
        host = FakeHost()
        host.add("v1.0.0", {}, draft=True)
        self.assertIn("the publish job will resume it", self.run_preflight(host))

    def test_stale_preflight_drafts_are_reported_not_deleted(self):
        host = FakeHost()
        host.add("release-preflight-7-ffffffff", {}, draft=True)
        out = self.run_preflight(host)
        self.assertIn("still has preflight drafts from earlier runs", out)
        self.assertIn("release-preflight-7-ffffffff", out)
        self.assertNotIn(("delete-release", "release-preflight-7-ffffffff"), host.calls)

    def test_refused_upload_still_deletes_the_draft(self):
        host = FakeHost()
        host.fail["bacnet-linux-amd64"] = "forbidden"
        with self.assertRaisesRegex(api.HttpFailure, "type not allowed"), \
                contextlib.redirect_stdout(io.StringIO()):
            api.preflight(host, "v1.0.0", COMMIT, PROBE, False)
        self.assertIn(("delete-release", PROBE), host.calls)
        self.assert_cleaned_up(host)

    def test_failed_final_check_still_deletes_the_draft(self):
        host = FakeHost()
        host.fail["rusty_bacnet-0.0.0.tar.gz"] = "corrupt"
        self.preflight_fails(host, "failed the final check")
        self.assert_cleaned_up(host)

    def test_lost_create_response_is_found_and_deleted(self):
        host = FakeHost()
        host.create_lost = True
        self.run_preflight(host)
        self.assertEqual(len([c for c in host.calls if c[0] == "create"]), 1)
        self.assert_cleaned_up(host)

    def test_draft_that_created_a_tag_fails(self):
        host = FakeHost(draft_creates_tag=True)
        message, _ = self.preflight_fails(host, f"now has a tag {PROBE}")
        self.assertIn("Delete it by hand", message)
        self.assert_cleaned_up(host)

    def test_drafts_missing_from_the_list_fail_and_are_deleted_by_id(self):
        host = FakeHost(hide_drafts=True)
        self.preflight_fails(host, "doesn't show the draft just created")
        self.assertIn(("delete-release", PROBE), host.calls)
        self.assert_cleaned_up(host)

    def test_failed_delete_after_a_passing_check_fails(self):
        host = FakeHost()
        host.fail_delete_release = True
        message, _ = self.preflight_fails(host, f"draft release {PROBE} may still be on Fake")
        self.assertIn("Delete it by hand", message)

    def test_failed_delete_after_a_failing_check_reports_both(self):
        host = FakeHost()
        host.fail_delete_release = True
        host.fail["bacnet-linux-amd64"] = "forbidden"
        with self.assertRaisesRegex(api.HttpFailure, "type not allowed"), \
                contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()) as err:
            api.preflight(host, "v1.0.0", COMMIT, PROBE, False)
        self.assertIn(f"::error::the preflight's draft release {PROBE} may still be on Fake", err.getvalue())

    def test_write_check_refuses_a_v_name(self):
        with self.assertRaisesRegex(api.ReleaseError, "must start with release-preflight-"):
            api.write_check(FakeHost(), "v9.9.9", COMMIT)


class MainTests(unittest.TestCase):
    def run_main(self, argv, env):
        out, err = io.StringIO(), io.StringIO()
        with mock.patch.dict(os.environ, env, clear=True), contextlib.redirect_stdout(out), \
                contextlib.redirect_stderr(err):
            code = api.main(argv)
        return code, out.getvalue(), err.getvalue()

    def test_missing_token_fails_clearly(self):
        with tempfile.TemporaryDirectory() as tmp:
            Path(tmp, "notes.md").write_text("n")
            code, _, err = self.run_main(["github", "--tag", "v1.0.0", "--notes", str(Path(tmp, "notes.md")),
                                          "--assets", tmp, "--commit", "abc"], {})
        self.assertEqual(code, 1)
        self.assertIn("GH_RELEASE_TOKEN is not set", err)
        self.assertIn("Contents read and write", err)

    def test_preflight_needs_the_token_to_publish(self):
        code, _, err = self.run_main(["github", "--preflight", "--tag", "v1.0.0", "--commit", "abc"], {})
        self.assertEqual(code, 1)
        self.assertIn("::error::preflight: GH_RELEASE_TOKEN is not set", err)
        self.assertIn("Nothing has been built or published", err)

    def test_preflight_dry_run_without_a_token_checks_only_the_tag(self):
        seen = []

        def tag_commit(self, tag):
            seen.append(self.http.auth)
            return "abc"

        with mock.patch.object(api.GitHub, "tag_commit", tag_commit):
            code, out, _ = self.run_main(
                ["github", "--preflight", "--dry-run", "--tag", "v1.0.0", "--commit", "abc"], {})
        self.assertEqual(code, 0)
        self.assertEqual(seen, [None])  # anonymous
        self.assertIn("GitHub has v1.0.0 at abc", out)
        self.assertIn("::notice::GH_RELEASE_TOKEN isn't set", out)

    def test_publish_needs_notes_and_assets(self):
        with self.assertRaises(SystemExit), contextlib.redirect_stderr(io.StringIO()):
            api.main(["forgejo", "--tag", "v1.0.0", "--commit", "abc"])


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

    def test_anonymous_client_sends_no_authorization(self):
        req = api.Http(None).build("GET", "https://api.github.com/repos/o/r/git/ref/tags/v1")
        self.assertNotIn("Authorization", req.unredirected_hdrs)
        self.assertNotIn("Authorization", req.headers)

    def fake_urlopen(self, errors):
        calls = []

        def urlopen(req, timeout):
            calls.append(req.get_method())
            error = errors.pop(0)
            if isinstance(error, int):
                raise urllib.error.HTTPError(req.full_url, error, "error", {}, io.BytesIO(b"oops"))
            raise error

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

    def test_truncated_response_is_an_uncertain_failure(self):
        http = api.Http("token t")
        urlopen, calls = self.fake_urlopen([IncompleteRead(b"x", 5) for _ in range(5)])
        with mock.patch.object(urllib.request, "urlopen", urlopen):
            with self.assertRaisesRegex(api.HttpFailure, "IncompleteRead") as caught:
                http.call("POST", "https://h.invalid/x", b"data", retry=False)
            self.assertTrue(caught.exception.uncertain)
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
        self.assertFalse(caught.exception.already_exists)
        self.assertEqual(calls, ["GET"])

    def test_already_exists(self):
        detail = '{"errors":[{"resource":"ReleaseAsset","code":"already_exists","field":"name"}]}'
        self.assertTrue(api.HttpFailure("x", 422, detail).already_exists)
        self.assertFalse(api.HttpFailure("x", 422, '{"errors":[{"code":"invalid"}]}').already_exists)
        self.assertFalse(api.HttpFailure("x", 502, detail).already_exists)

    def recorded(self, host):
        seen = []

        def call(method, url, body=None, **kwargs):
            seen.append((method, url, body, kwargs))
            return {"draft": False}

        return seen, mock.patch.object(host.http, "call", call)

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
        self.assertIsNone(api.reported_digest({"digest": None}))
        self.assertIsNone(api.reported_digest({}))

    def test_github_publish_keeps_latest_by_date_and_version(self):
        host = api.GitHub("o/r", "t")
        seen, patch = self.recorded(host)
        with patch:
            host.publish_release({"id": 7})
        self.assertEqual(seen, [("PATCH", "https://api.github.com/repos/o/r/releases/7",
                                 {"draft": False, "make_latest": "legacy"}, {})])

    def test_deletes_tolerate_404(self):
        for host in (api.Forgejo("o/r", "https://f.invalid", "t"), api.GitHub("o/r", "t")):
            seen, patch = self.recorded(host)
            with patch:
                host.delete_asset({"id": 7}, {"id": 8})
                host.delete_release({"id": 7})
            with self.subTest(host=host.label):
                self.assertEqual([(m, kw) for m, _, _, kw in seen], [("DELETE", {"ok404": True})] * 2)

    def test_forgejo_tag_list_is_paged_to_the_end(self):
        host = api.Forgejo("o/r", "https://f.invalid", "t")
        pages = [[{"name": f"v{i}"} for i in range(50)], [{"name": "release-preflight-1-ab"}], []]
        seen = []
        with mock.patch.object(host.http, "call", lambda method, url, **kw: seen.append(url) or pages.pop(0)):
            self.assertTrue(host.tag_exists("release-preflight-1-ab"))
        self.assertIn("/repos/o/r/tags?page=2&limit=50", seen[1])
        self.assertEqual(len(seen), 3)  # to the empty page


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


if __name__ == "__main__":
    unittest.main()
