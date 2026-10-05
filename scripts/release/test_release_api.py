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
    """Stands in for GitHub: holds releases in memory, records every call and,
    like GitHub, refuses any asset change once a release is public."""

    label = "Fake"
    published_hint = "Fake releases are immutable."

    def __init__(self):
        self.releases = []
        self.calls = []
        # asset name -> how its next upload goes wrong:
        #   lost      stored, response lost
        #   refused   not stored, HTTP 502
        #   exists    stored, then HTTP 422 already_exists (as after a lost response)
        #   corrupt   other bytes stored, success
        #   dup       stored twice, success
        #   stray     stored, plus an incomplete upload of another file
        self.fail = {}
        self.create_lost = False
        self.ids = iter(range(100, 10_000))

    def add(self, tag, files, draft, commit=COMMIT):
        release = {"id": next(self.ids), "tag_name": tag, "draft": draft, "target_commitish": commit,
                   "assets": []}
        self.releases.append(release)
        for name, data in files.items():
            self._store(release, name, data)
        return release

    def _store(self, release, name, data, state="uploaded"):
        release["assets"].append({"id": next(self.ids), "name": name, "size": len(data), "state": state,
                                  "data": data, "digest": "sha256:" + api.sha256_bytes(data)})

    def _live(self, release):
        return next(r for r in self.releases if r["id"] == release["id"])

    def _writable(self, release):
        live = self._live(release)
        if not live["draft"]:
            raise Immutable(f"release {live['tag_name']} is published")
        return live

    def list_releases(self):
        return copy.deepcopy(self.releases)

    def find_release(self, tag):
        return api.pick_release(self.list_releases(), tag)

    def refresh(self, release):
        return copy.deepcopy(self._live(release))

    def create_draft(self, tag, name, notes, commit, prerelease):
        self.calls.append(("create", tag, name, commit, prerelease))
        release = self.add(tag, {}, draft=True, commit=commit)
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

    def download(self, release, item):
        self.calls.append(("download", item["name"]))
        return item["data"]

    def asset_digest(self, release, item):
        self.calls.append(("digest", item["name"]))
        return item["digest"].removeprefix("sha256:")

    def publish_release(self, release):
        self.calls.append(("publish",))
        self._live(release)["draft"] = False
        return copy.deepcopy(self._live(release))

    def files(self, tag="v1.0.0"):
        release = next(r for r in self.releases if r["tag_name"] == tag)
        return {a["name"]: a["data"] for a in release["assets"]}


WRITES = ("create", "upload", "delete", "publish")


def writes(host):
    return [c for c in host.calls if c[0] in WRITES]


WHEEL, BINARY = b"wheel", b"binary"
SUMS_OK = api.sums_text({"bacnet-linux-amd64": api.sha256_bytes(BINARY), "x.whl": api.sha256_bytes(WHEEL)}).encode()
SUMS_SHA = api.sha256_bytes(SUMS_OK)
COMPLETE = {"x.whl": WHEEL, "bacnet-linux-amd64": BINARY, "SHA256SUMS": SUMS_OK}


class AssetsTestCase(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.dir = Path(self.tmp.name)
        (self.dir / "x.whl").write_bytes(WHEEL)
        (self.dir / "bacnet-linux-amd64").write_bytes(BINARY)

    def tearDown(self):
        self.tmp.cleanup()

    def stage(self, host, tag="v1.0.0"):
        with contextlib.redirect_stdout(io.StringIO()) as out:
            release, sums = api.stage(host, tag, "notes", self.dir, COMMIT)
        return release, sums, out.getvalue()

    def stage_fails(self, host, pattern):
        with self.assertRaisesRegex(api.ReleaseError, pattern) as caught, \
                contextlib.redirect_stdout(io.StringIO()):
            api.stage(host, "v1.0.0", "notes", self.dir, COMMIT)
        self.assertNotIn(("publish",), host.calls)
        return str(caught.exception)

    def publish(self, host, staged):
        with contextlib.redirect_stdout(io.StringIO()) as out:
            api.publish(host, "v1.0.0", self.dir, staged)
        return out.getvalue()

    def plan(self, host):
        with contextlib.redirect_stdout(io.StringIO()) as out:
            api.plan(host, "v1.0.0", self.dir, COMMIT)
        return out.getvalue()


class StageTests(AssetsTestCase):
    def test_new_draft_is_filled_checked_and_left_a_draft(self):
        host = FakeHost()
        release, sums, out = self.stage(host, tag="v1.0.0-rc.1")
        self.assertEqual(writes(host), [
            ("create", "v1.0.0-rc.1", "Rusty BACnet v1.0.0-rc.1", COMMIT, True),
            ("upload", "bacnet-linux-amd64"), ("upload", "x.whl"), ("upload", "SHA256SUMS")])
        self.assertTrue(host.releases[0]["draft"])
        self.assertEqual(host.files("v1.0.0-rc.1")["SHA256SUMS"], SUMS_OK)
        self.assertEqual((release["id"], sums), (host.releases[0]["id"], SUMS_SHA))
        self.assertIn("final check: 3 assets as expected (reported sha256 digest)", out)

    def test_a_release_is_not_a_prerelease(self):
        host = FakeHost()
        self.stage(host)
        self.assertEqual(writes(host)[0], ("create", "v1.0.0", "Rusty BACnet v1.0.0", COMMIT, False))

    def test_an_earlier_build_on_the_draft_is_replaced(self):
        # The draft must end up with this run's files: the ones that were
        # tested and that PyPI gets.
        host = FakeHost()
        host.add("v1.0.0", {"x.whl": b"older wheel", "bacnet-linux-amd64": BINARY}, draft=True)
        _, sums, out = self.stage(host)
        self.assertEqual(writes(host), [("delete", "x.whl"), ("upload", "x.whl"), ("upload", "SHA256SUMS")])
        self.assertIn("delete x.whl: it differs from this run's file, which replaces it", out)
        self.assertIn("resuming draft release v1.0.0", out)
        self.assertEqual(host.files()["SHA256SUMS"], SUMS_OK)
        self.assertEqual(sums, SUMS_SHA)

    def test_a_stale_sums_is_replaced(self):
        host = FakeHost()
        host.add("v1.0.0", {"x.whl": WHEEL, "SHA256SUMS": b"00  x.whl\n"}, draft=True)
        self.stage(host)
        self.assertEqual(writes(host), [
            ("upload", "bacnet-linux-amd64"), ("delete", "SHA256SUMS"), ("upload", "SHA256SUMS")])
        self.assertEqual(host.files()["SHA256SUMS"], SUMS_OK)

    def test_a_complete_draft_is_left_alone(self):
        host = FakeHost()
        host.add("v1.0.0", COMPLETE, draft=True)
        _, sums, out = self.stage(host)
        self.assertEqual(writes(host), [])
        self.assertEqual(sums, SUMS_SHA)
        self.assertIn("skip SHA256SUMS: up to date", out)

    def test_a_draft_for_another_commit_is_refused(self):
        host = FakeHost()
        host.add("v1.0.0", {"x.whl": WHEEL}, draft=True, commit="beef")
        self.assertIn("Delete that draft", self.stage_fails(host, "made for beef, not c0ffee"))
        self.assertEqual(writes(host), [])

    def test_extra_assets_are_deleted(self):
        host = FakeHost()
        host.add("v1.0.0", {"x.whl": WHEEL, "old-tool.exe": b"old", "SHA256SUMS": b"00  old-tool.exe\n"},
                 draft=True)
        self.stage(host)
        self.assertEqual(writes(host), [
            ("delete", "old-tool.exe"), ("upload", "bacnet-linux-amd64"), ("delete", "SHA256SUMS"),
            ("upload", "SHA256SUMS")])
        self.assertEqual(set(host.files()), {"x.whl", "bacnet-linux-amd64", "SHA256SUMS"})

    def test_every_copy_of_a_duplicated_name_is_deleted(self):
        host = FakeHost()
        release = host.add("v1.0.0", {"x.whl": WHEEL}, draft=True)
        host._store(release, "x.whl", WHEEL)
        self.stage(host)
        self.assertEqual(writes(host)[:3], [("delete", "x.whl"), ("delete", "x.whl"), ("upload", "bacnet-linux-amd64")])
        self.assertEqual([a["name"] for a in host.releases[0]["assets"]].count("x.whl"), 1)

    def test_a_duplicate_left_by_an_upload_fails_the_final_check(self):
        host = FakeHost()
        host.fail["x.whl"] = "dup"
        self.assertIn("several assets are named x.whl", self.stage_fails(host, "failed the final check"))
        self.assertTrue(host.releases[0]["draft"])

    def test_a_corrupted_upload_fails_the_final_check(self):
        host = FakeHost()
        host.fail["x.whl"] = "corrupt"
        message = self.stage_fails(host, "failed the final check, so it stays a draft")
        self.assertIn("x.whl is 6 bytes, expected 5", message)

    def test_a_digest_mismatch_of_the_same_size_fails_the_final_check(self):
        host = FakeHost()
        release = host.add("v1.0.0", {}, draft=True)
        original = host.upload

        def upload(rel, path):
            original(rel, path)
            if path.name == "x.whl":  # same size, other bytes
                host._live(release)["assets"][-1]["digest"] = "sha256:" + api.sha256_bytes(b"WHEEL")

        host.upload = upload
        message = self.stage_fails(host, "failed the final check")
        self.assertIn(f"x.whl has sha256 {api.sha256_bytes(b'WHEEL')}, expected {api.sha256_bytes(WHEEL)}",
                      message)

    def test_the_sums_digest_is_checked_too(self):
        host = FakeHost()
        host.fail["SHA256SUMS"] = "corrupt"
        self.assertIn("SHA256SUMS is", self.stage_fails(host, "failed the final check"))

    def test_an_incomplete_entry_fails_the_final_check(self):
        host = FakeHost()
        host.fail["SHA256SUMS"] = "stray"
        message = self.stage_fails(host, "failed the final check")
        self.assertIn("late.bin is not completely uploaded (state starter)", message)
        self.assertIn("late.bin isn't part of this release", message)

    def test_a_missing_digest_falls_back_to_downloading(self):
        host = FakeHost()
        host.add("v1.0.0", COMPLETE, draft=True)
        for item in host.releases[0]["assets"]:
            del item["digest"]
        host.asset_digest = lambda release, item: api.sha256_bytes(host.download(release, item))
        _, _, out = self.stage(host)
        self.assertIn("(downloaded sha256)", out)
        self.assertEqual(writes(host), [])

    def test_a_lost_upload_response_is_not_sent_again(self):
        host = FakeHost()
        host.fail["x.whl"] = "lost"
        _, _, out = self.stage(host)
        self.assertEqual([c for c in host.calls if c == ("upload", "x.whl")], [("upload", "x.whl")])
        self.assertIn("x.whl arrived after all", out)
        self.assertEqual(host.files()["SHA256SUMS"], SUMS_OK)

    def test_already_exists_with_the_same_bytes_is_accepted(self):
        host = FakeHost()
        host.fail["x.whl"] = "exists"
        _, _, out = self.stage(host)
        self.assertEqual([c for c in host.calls if c == ("upload", "x.whl")], [("upload", "x.whl")])
        self.assertIn("x.whl arrived after all", out)

    def test_a_refused_upload_is_sent_again(self):
        host = FakeHost()
        host.fail["x.whl"] = "refused"
        self.stage(host)
        self.assertEqual([c for c in host.calls if c == ("upload", "x.whl")], [("upload", "x.whl")] * 2)
        self.assertEqual(host.files()["SHA256SUMS"], SUMS_OK)

    def test_a_lost_create_response_reuses_the_draft(self):
        host = FakeHost()
        host.create_lost = True
        self.stage(host)
        self.assertEqual(len(host.releases), 1)
        self.assertEqual([c[0] for c in writes(host)].count("create"), 1)

    def test_a_complete_published_release_is_only_checked(self):
        host = FakeHost()
        release = host.add("v1.0.0", COMPLETE, draft=False)
        found, sums, out = self.stage(host)
        self.assertEqual(writes(host), [])
        self.assertEqual((found["id"], sums), (release["id"], SUMS_SHA))
        self.assertIn("is complete; the publish job will only check it again", out)

    def test_an_incomplete_published_release_fails_without_writing(self):
        host = FakeHost()
        host.add("v1.0.0", {"x.whl": WHEEL}, draft=False)
        message = self.stage_fails(host, "published but incomplete")
        self.assertEqual(writes(host), [])
        for want in ("bacnet-linux-amd64 is missing", "SHA256SUMS is missing", "immutable"):
            self.assertIn(want, message)

    def test_a_published_asset_that_doesnt_match_sums_is_a_problem(self):
        host = FakeHost()
        sums = api.sums_text({"bacnet-linux-amd64": api.sha256_bytes(BINARY), "x.whl": "00"}).encode()
        host.add("v1.0.0", {"x.whl": WHEEL, "bacnet-linux-amd64": BINARY, "SHA256SUMS": sums}, draft=False)
        self.stage_fails(host, "x.whl doesn't match its SHA256SUMS entry")

    def test_a_published_release_with_duplicate_names_is_a_problem(self):
        host = FakeHost()
        release = host.add("v1.0.0", COMPLETE, draft=False)
        host._store(release, "x.whl", WHEEL)
        self.stage_fails(host, "several assets are named x.whl")

    def test_the_fake_host_refuses_changes_after_publishing(self):
        # Publishing before the uploads would fail here, as it would on GitHub.
        host = FakeHost()
        release = host.add("v1.0.0", {}, draft=True)
        host.publish_release(release)
        with self.assertRaises(Immutable):
            host.upload(release, self.dir / "x.whl")
        with self.assertRaises(Immutable):
            host.delete_asset(release, {"id": 0, "name": "x.whl"})


class PublishTests(AssetsTestCase):
    def test_the_staged_draft_is_published_without_any_other_write(self):
        host = FakeHost()
        release, sums, _ = self.stage(host)
        host.calls.clear()
        out = self.publish(host, (str(release["id"]), sums))
        self.assertEqual(writes(host), [("publish",)])
        self.assertFalse(host.releases[0]["draft"])
        self.assertIn("done: v1.0.0 is public", out)

    def test_another_release_for_the_tag_isnt_published(self):
        host = FakeHost()
        release, sums, _ = self.stage(host)
        host.calls.clear()
        for staged in ((str(release["id"] + 1), sums), ("7", sums)):
            with self.assertRaisesRegex(api.ReleaseError, "isn't the draft this run staged"):
                self.publish(host, staged)
        host.releases.clear()
        with self.assertRaisesRegex(api.ReleaseError, r"v1.0.0 \(none\) isn't the draft"):
            self.publish(host, (str(release["id"]), sums))
        self.assertEqual(writes(host), [])

    def test_a_draft_changed_after_staging_isnt_published(self):
        host = FakeHost()
        release, sums, _ = self.stage(host)
        host.delete_asset(release, host.releases[0]["assets"][0])
        host._store(host.releases[0], "extra.bin", b"x")
        host.calls.clear()
        with self.assertRaisesRegex(api.ReleaseError, "failed the final check") as caught:
            self.publish(host, (release["id"], sums))
        self.assertIn("bacnet-linux-amd64 is missing", str(caught.exception))
        self.assertIn("extra.bin isn't part of this release", str(caught.exception))
        self.assertEqual(writes(host), [])

    def test_other_local_files_than_the_staged_ones_arent_published(self):
        host = FakeHost()
        release, sums, _ = self.stage(host)
        (self.dir / "x.whl").write_bytes(b"rebuilt")
        host.calls.clear()
        with self.assertRaisesRegex(api.ReleaseError, "aren't the ones it staged"):
            self.publish(host, (release["id"], sums))
        self.assertEqual(writes(host), [])

    def test_an_already_published_release_is_only_checked(self):
        host = FakeHost()
        release, sums, _ = self.stage(host)
        host.publish_release(release)
        host.calls.clear()
        out = self.publish(host, (release["id"], sums))
        self.assertEqual(writes(host), [])
        self.assertIn("is complete; nothing to do", out)

    def test_an_incomplete_published_release_fails(self):
        host = FakeHost()
        release = host.add("v1.0.0", {"x.whl": WHEEL}, draft=False)
        with self.assertRaisesRegex(api.ReleaseError, "published but incomplete"):
            self.publish(host, (release["id"], SUMS_SHA))
        self.assertEqual(writes(host), [])


class PlanTests(AssetsTestCase):
    def test_no_release_writes_nothing(self):
        host = FakeHost()
        out = self.plan(host)
        self.assertEqual(writes(host), [])
        self.assertIn(f"would create draft release v1.0.0 at {COMMIT}", out)
        self.assertIn("would upload x.whl", out)
        self.assertIn("would upload SHA256SUMS for 2 assets", out)

    def test_a_draft_is_planned_and_read(self):
        host = FakeHost()
        host.add("v1.0.0", {"x.whl": WHEEL, "big.tar.gz": b"x" * 100, "bacnet-linux-amd64": b"older"},
                 draft=True)
        out = self.plan(host)
        self.assertEqual(writes(host), [])
        self.assertIn("would resume draft release v1.0.0", out)
        self.assertIn("skip x.whl: already on the draft", out)
        self.assertIn("would delete big.tar.gz: it isn't part of this release", out)
        self.assertIn("would delete bacnet-linux-amd64: it differs from this run's file", out)
        self.assertIn("would upload bacnet-linux-amd64", out)
        self.assertIn("download check: bacnet-linux-amd64 (5 bytes) read", out)

    def test_a_draft_for_another_commit_only_warns(self):
        host = FakeHost()
        host.add("v1.0.0", {"x.whl": WHEEL}, draft=True, commit="beef")
        out = self.plan(host)
        self.assertEqual(writes(host), [])
        self.assertIn("::warning::Fake has a draft release v1.0.0", out)
        self.assertIn("A release would stop here.", out)

    def test_a_published_release_is_checked_and_problems_only_warn(self):
        host = FakeHost()
        host.add("v1.0.0", {"x.whl": WHEEL}, draft=False)
        out = self.plan(host)
        self.assertEqual(writes(host), [])
        self.assertIn("::warning::Fake release v1.0.0 is published but incomplete", out)
        host = FakeHost()
        host.add("v1.0.0", COMPLETE, draft=False)
        self.assertIn("is complete; a release would only check it", self.plan(host))


class FakeTags:
    def __init__(self, commit):
        self.commit = commit
        self.label = "GitHub"

    def tag_commit(self, tag):
        return self.commit


class CheckTagTests(unittest.TestCase):
    def test_a_tag_elsewhere_fails_a_release_and_warns_a_dry_run(self):
        with self.assertRaisesRegex(api.ReleaseError, "points at bbb, not aaa"):
            api.check_tag(FakeTags("bbb"), "v1", "aaa")
        with contextlib.redirect_stdout(io.StringIO()) as out:
            api.check_tag(FakeTags("bbb"), "v1", "aaa", dry_run=True)
        self.assertIn("::warning::GitHub's v1 points at bbb", out.getvalue())

    def test_a_missing_tag_fails_a_release_and_warns_a_dry_run(self):
        with self.assertRaisesRegex(api.ReleaseError, "has no tag v1"):
            api.check_tag(FakeTags(None), "v1", "aaa")
        with contextlib.redirect_stdout(io.StringIO()) as out:
            api.check_tag(FakeTags(None), "v1", "aaa", dry_run=True)
        self.assertIn("a release would stop here", out.getvalue())

    def test_the_right_tag_passes(self):
        with contextlib.redirect_stdout(io.StringIO()) as out:
            api.check_tag(FakeTags("aaa"), "v1", "aaa")
        self.assertIn("GitHub has v1 at aaa", out.getvalue())


class MainTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.dir = Path(self.tmp.name)
        (self.dir / "notes.md").write_text("n")
        (self.dir / "assets").mkdir()
        (self.dir / "assets" / "x.whl").write_bytes(WHEEL)

    def tearDown(self):
        self.tmp.cleanup()

    def run_main(self, argv, env):
        out, err = io.StringIO(), io.StringIO()
        with mock.patch.dict(os.environ, env, clear=True), contextlib.redirect_stdout(out), \
                contextlib.redirect_stderr(err):
            code = api.main(argv)
        return code, out.getvalue(), err.getvalue()

    def base(self, command):
        return [command, "--tag", "v1.0.0", "--commit", "abc", "--assets", str(self.dir / "assets")]

    def test_a_missing_token_fails_clearly(self):
        for argv in (self.base("stage") + ["--notes", str(self.dir / "notes.md")],
                     self.base("publish") + ["--staged-release", "7", "--staged-sums", "ab"]):
            with self.subTest(command=argv[0]):
                code, _, err = self.run_main(argv, {})
                self.assertEqual(code, 1)
                self.assertIn("GITHUB_TOKEN is not set", err)

    def test_publish_fails_closed_without_staged_values(self):
        # Empty values (an unset job output) must not publish anything:
        # argparse stops before any request.
        for extra in ([], ["--staged-release", "", "--staged-sums", ""], ["--staged-release", "7"],
                      ["--staged-sums", "ab"], ["--staged-release", "7", "--staged-sums", ""]):
            with self.subTest(extra=extra), \
                    mock.patch.object(api.GitHub, "find_release") as find, \
                    mock.patch.object(api.GitHub, "publish_release") as publish, \
                    mock.patch.object(api.GitHub, "tag_commit") as tag:
                with self.assertRaises(SystemExit) as caught:
                    self.run_main(self.base("publish") + extra, {"GITHUB_TOKEN": "t"})
                self.assertNotEqual(caught.exception.code, 0)
                find.assert_not_called()
                publish.assert_not_called()
                tag.assert_not_called()

    def test_a_tag_elsewhere_stops_before_any_release_call(self):
        with mock.patch.object(api.GitHub, "tag_commit", return_value="beef"), \
                mock.patch.object(api.GitHub, "list_releases") as releases:
            code, _, err = self.run_main(self.base("stage") + ["--notes", str(self.dir / "notes.md")],
                                         {"GITHUB_TOKEN": "t"})
        self.assertEqual(code, 1)
        self.assertIn("points at beef, not abc", err)
        releases.assert_not_called()

    def test_stage_writes_its_outputs(self):
        output = self.dir / "output"
        with mock.patch.object(api.GitHub, "tag_commit", return_value="abc"), \
                mock.patch.object(api, "stage", return_value=({"id": 42}, "f" * 64)) as stage:
            code, _, _ = self.run_main(self.base("stage") + ["--notes", str(self.dir / "notes.md")],
                                       {"GITHUB_TOKEN": "t", "GITHUB_OUTPUT": str(output),
                                        "GITHUB_REPOSITORY": "o/r"})
        self.assertEqual(code, 0)
        self.assertEqual(output.read_text(), f"release_id=42\nsums_sha256={'f' * 64}\n")
        self.assertEqual(stage.call_args.args[0].repo, "o/r")
        self.assertEqual(stage.call_args.args[1:3], ("v1.0.0", "n"))

    def test_plan_runs_without_a_token(self):
        seen = []

        def tag_commit(host, tag):
            seen.append(host.http.auth)
            return "abc"

        with mock.patch.object(api.GitHub, "tag_commit", tag_commit), \
                mock.patch.object(api.GitHub, "list_releases", return_value=[]):
            code, out, _ = self.run_main(self.base("plan"), {})
        self.assertEqual(code, 0)
        self.assertEqual(seen, [None])  # anonymous
        self.assertIn("dry run: no writes", out)
        self.assertIn("would create draft release v1.0.0 at abc", out)


class HttpTests(unittest.TestCase):
    def test_the_token_is_never_redirected(self):
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

    def test_an_anonymous_client_sends_no_authorization(self):
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

    def test_a_truncated_response_is_an_uncertain_failure(self):
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

    def test_draft_assets_are_downloaded_through_the_api(self):
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

    def test_the_digest_comes_from_the_asset_when_reported(self):
        host = api.GitHub("o/r", "t")
        self.assertEqual(host.asset_digest({}, {"digest": "sha256:abc"}), "abc")
        self.assertIsNone(api.reported_digest({"digest": None}))
        self.assertIsNone(api.reported_digest({}))

    def test_publishing_keeps_latest_by_date_and_version(self):
        host = api.GitHub("o/r", "t")
        seen, patch = self.recorded(host)
        with patch:
            host.publish_release({"id": 7})
        self.assertEqual(seen, [("PATCH", "https://api.github.com/repos/o/r/releases/7",
                                 {"draft": False, "make_latest": "legacy"}, {})])

    def test_deletes_tolerate_404(self):
        host = api.GitHub("o/r", "t")
        seen, patch = self.recorded(host)
        with patch:
            host.delete_asset({"id": 7}, {"id": 8})
            host.drop_incomplete({"assets": [{"id": 9, "name": "x", "state": "starter"}]})
        self.assertEqual([(m, kw) for m, _, _, kw in seen], [("DELETE", {"ok404": True})] * 2)

    def test_an_annotated_tag_is_followed_to_its_commit(self):
        host = api.GitHub("o/r", "t")
        answers = [{"object": {"type": "tag", "sha": "t1"}}, {"object": {"type": "commit", "sha": "c1"}}]
        with mock.patch.object(host.http, "call", lambda method, url, **kw: answers.pop(0)):
            self.assertEqual(host.tag_commit("v1"), "c1")
        with mock.patch.object(host.http, "call", lambda method, url, **kw: None):
            self.assertIsNone(host.tag_commit("v1"))


if __name__ == "__main__":
    unittest.main()
