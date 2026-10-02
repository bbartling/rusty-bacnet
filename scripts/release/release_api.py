#!/usr/bin/env python3
"""Publish a Forgejo or GitHub release as a draft, then make it public (#943).

    release_api.py forgejo --tag v0.12.0 --commit SHA --notes notes.md --assets DIR [--dry-run]
    release_api.py github --tag v0.12.0 --commit SHA --notes notes.md --assets DIR \
        [--wait-tag SECONDS] (--dry-run | --staged-release ID --staged-sums SHA256)
    release_api.py forgejo|github --preflight --tag v0.12.0 --commit SHA \
        [--wait-tag SECONDS] [--dry-run]

On GitHub, release_smoke.py does steps 1 to 4 below for the smoke test (#951),
with stage(). The GitHub copy then publishes only that draft: a GitHub publish
needs --staged-release and --staged-sums, both non-empty, and allows no change
to the draft (see publish()). Forgejo's release does all five steps here.

GitHub releases in this repository are immutable once published: their assets
can't be added, replaced or deleted, and the tag can't be reused. So a release
is built as a draft and published by the very last call:

1. find the release for the tag in the release list, drafts included (the
   by-tag endpoints don't return drafts); create a draft at --commit if there
   is none;
2. upload the assets the draft doesn't have yet;
3. upload SHA256SUMS, computed over the draft's final asset set;
4. check every asset once more against what this run uploaded or verified;
5. publish the draft.

Safe to re-run. A draft left by an earlier run is resumed with its notes, if
it was made for --commit; a draft for another commit stops the run. Assets on
it that aren't part of this release, and every copy of a duplicated name, are
deleted first (Forgejo deletes a run's artifacts when any of its jobs is
re-run, so a re-run always rebuilds). On GitHub, an asset the earlier run
uploaded is kept, with the checksum GitHub reports for it. Forgejo can't serve
a private repository's assets to the job token, so this script can't checksum
them; on a resumed Forgejo draft, this run's files replace whatever is there.
A release that is already published is only checked, never changed: every
asset and SHA256SUMS must be there, and on GitHub each asset must match
SHA256SUMS. Forgejo releases follow the same order, so releases/latest never
shows a half-uploaded release.

Step 4, the last check before the irreversible publish: the draft must hold
exactly the expected names, once each, every one completely uploaded. On
GitHub each asset's reported sha256 digest must equal the expected one (the
local file's, the verified digest of a kept asset, or that of the SHA256SUMS
text this run computed); without a digest the asset is downloaded and hashed.
Forgejo reports no digest and won't serve the assets, so there the check is
each asset's size against the local file's.

--dry-run makes no write at all. It reads the release list, plans the
uploads, checks a published release and, on GitHub, downloads one existing
asset to show that a resume could read the release.

--preflight runs before anything is built and checks that the release can be
published: on GitHub, that the push mirror has the tag at --commit (waiting up
to --wait-tag seconds; the repository is public, so this needs no token), then
on either host that the token can list releases, and what state the release
for the tag is in. Unless --dry-run, it then makes a disposable draft (named
release-preflight-<run id>-<random>, so no v* tag rule applies, at --commit),
checks that the release list shows it, uploads small files named like each
kind of release asset, checks them as step 4 would, and deletes the draft even
if a step failed, finally checking that no release or tag of that name is left.

Environment (values are never printed):
- forgejo: FORGEJO_TOKEN, plus GITHUB_SERVER_URL and GITHUB_REPOSITORY, which
  Forgejo Actions sets for every job;
- github: GH_RELEASE_TOKEN, a fine-grained token with Contents read and write
  on GITHUB_REPO (default jscott3201/rusty-bacnet), and Actions read and write
  for release_smoke.py. A preflight dry run without it checks only the tag.

For github, --wait-tag polls until the push mirror has the tag, and the tag
must point at --commit.
"""

import argparse
import collections
import gzip
import hashlib
import json
import os
import secrets
import sys
import tempfile
import time
import urllib.error
import urllib.parse
import urllib.request
import uuid
from http.client import HTTPException
from pathlib import Path

SUMS = "SHA256SUMS"
USER_AGENT = "rusty-bacnet-release (+https://github.com/jscott3201/rusty-bacnet)"
RETRY_DELAY = 5  # seconds, times the attempt number; tests set it to 0
GITHUB_REPO = "jscott3201/rusty-bacnet"
PROBE_PREFIX = "release-preflight-"
# A dry run's smoke test (#951) runs against a throwaway GitHub draft named
# release-smoke-<run id>, which release_smoke.py deletes again.
SMOKE_PREFIX = "release-smoke-"
# The preflight's write check uploads one file of each kind a release has, named
# like it, so the host's allowed attachment types are proven: an extension-less
# file (the Linux and macOS CLI binaries, SHA256SUMS, THIRD-PARTY-NOTICES), the
# Windows CLI's .exe, a wheel and an sdist.
PROBE_ASSETS = {
    "bacnet-linux-amd64": b"\x7f",
    "bacnet-windows-amd64.exe": b"MZ",
    "rusty_bacnet-0.0.0-py3-none-any.whl": b"PK\x05\x06" + bytes(18),  # an empty zip archive
    "rusty_bacnet-0.0.0.tar.gz": gzip.compress(b"", mtime=0),
}


class ReleaseError(Exception):
    """A condition the release can't safely continue past."""


class HttpFailure(ReleaseError):
    """A request failed. code is the HTTP status, or None if no response came back."""

    def __init__(self, message, code=None, detail=""):
        super().__init__(message)
        self.code = code
        self.detail = detail

    @property
    def uncertain(self):
        """True if the server may have carried out the request anyway."""
        return self.code is None or self.code >= 500

    @property
    def already_exists(self):
        """GitHub refused an upload because the release has an asset of that name:
        perhaps this very file, from an attempt whose response was lost."""
        return self.code == 422 and "already_exists" in self.detail


def sha256_bytes(data):
    return hashlib.sha256(data).hexdigest()


def sha256(path):
    digest = hashlib.sha256()
    with open(path, "rb") as f:
        for block in iter(lambda: f.read(1 << 20), b""):
            digest.update(block)
    return digest.hexdigest()


def sums_text(digests):
    """SHA256SUMS content for {name: sha256}, in sha256sum's format."""
    return "".join(f"{digest}  {name}\n" for name, digest in sorted(digests.items()))


def parse_sums(text):
    sums = {}
    for line in text.splitlines():
        if line.strip():
            digest, name = line.split(maxsplit=1)
            sums[name.lstrip("*")] = digest
    return sums


def reported_digest(item):
    """The sha256 a host reports for an asset (GitHub's `digest`), or None."""
    digest = item.get("digest") or ""
    return digest.removeprefix("sha256:") if digest.startswith("sha256:") else None


class Http:
    """A minimal client. The token only ever goes into an unredirected header,
    so a redirect (to release storage, or to a sign-in page) never carries it.
    Without auth_header, requests are anonymous."""

    def __init__(self, auth_header=None, headers=None):
        self.auth = auth_header
        self.headers = {"User-Agent": USER_AGENT, **(headers or {})}

    def build(self, method, url, data=None, content_type=None, accept=None):
        req = urllib.request.Request(url, data=data, method=method)
        for key, value in self.headers.items():
            req.add_header(key, value)
        if accept:
            req.add_header("Accept", accept)
        if data is not None:
            req.add_header("Content-Type", content_type)
        if self.auth:
            req.add_unredirected_header("Authorization", self.auth)
        return req

    def call(self, method, url, body=None, content_type="application/json", accept=None,
             ok404=False, retry=True, raw=False):
        """Send one request, retrying 5xx and network errors when retry is set.

        Only idempotent requests may retry: a POST whose response is lost may
        still have been carried out, so its caller checks before sending again.
        """
        data = json.dumps(body).encode() if isinstance(body, dict) else body
        where = f"{method} {url.split('?')[0]}"
        attempts = 4 if retry else 1
        for attempt in range(1, attempts + 1):
            req = self.build(method, url, data, content_type, accept)
            try:
                with urllib.request.urlopen(req, timeout=300) as resp:
                    payload = resp.read()
                    is_json = not raw and "json" in resp.headers.get("Content-Type", "")
                    return json.loads(payload) if payload and is_json else payload
            except urllib.error.HTTPError as err:
                with err:
                    detail = err.read().decode(errors="replace")[:500]
                if err.code == 404 and ok404:
                    return None
                failure = HttpFailure(f"{where} returned HTTP {err.code}: {detail}", err.code, detail)
            except (OSError, HTTPException) as err:  # URLError, timeouts, resets, truncated bodies
                failure = HttpFailure(f"{where} failed: {getattr(err, 'reason', err)}")
            if not failure.uncertain or attempt == attempts:
                raise failure
            time.sleep(RETRY_DELAY * attempt)
        raise AssertionError("unreachable")


def multipart(field, filename, payload):
    boundary = uuid.uuid4().hex
    head = (
        f'--{boundary}\r\nContent-Disposition: form-data; name="{field}"; filename="{filename}"\r\n'
        "Content-Type: application/octet-stream\r\n\r\n"
    ).encode()
    return head + payload + f"\r\n--{boundary}--\r\n".encode(), f"multipart/form-data; boundary={boundary}"


def checked_download(http, url, expected_size, accept=None):
    data = http.call("GET", url, accept=accept, raw=True)
    if len(data) != expected_size:
        raise ReleaseError(f"downloading {url.split('?')[0]} gave {len(data)} bytes, expected "
                           f"{expected_size}; is the token allowed to read the release?")
    return data


def list_pages(http, url, page_size):
    """Every item of a paged list. Stops at an empty page, which is right even
    if the server caps the page size below the one asked for."""
    found = []
    for page in range(1, 51):
        batch = http.call("GET", f"{url}{'&' if '?' in url else '?'}page={page}&{page_size}")
        if not batch:
            return found
        found += batch
    raise ReleaseError(f"{url} has more than 50 pages")


def pick_release(releases, tag):
    """The release for tag: the published one, or the only draft."""
    matches = [r for r in releases if r.get("tag_name") == tag]
    published = [r for r in matches if not r.get("draft")]
    drafts = [r for r in matches if r.get("draft")]
    if len(published) > 1:
        raise ReleaseError(f"{len(published)} published releases have tag {tag}")
    if published:
        for draft in drafts:
            print(f"note: ignoring draft release {draft['id']}, because {tag} is already published")
        return published[0]
    if len(drafts) > 1:
        ids = ", ".join(str(d["id"]) for d in drafts)
        raise ReleaseError(f"several draft releases have tag {tag} ({ids}); delete all but one, then re-run")
    return drafts[0] if drafts else None


class Forgejo:
    label = "Forgejo"
    # The job token can't read attachments on Forgejo's web routes, which are
    # the only way to download them, for a private repository.
    can_read_assets = False
    staged_only = False
    published_hint = (
        "This workflow never changes a published release. Fix it on Forgejo by hand, or delete"
        " the release so that the next run builds it again as a draft."
    )

    def __init__(self, repo, server, token):
        self.repo = repo
        self.api = f"{server}/api/v1/repos/{repo}"
        self.http = Http(f"token {token}", {"Accept": "application/json"})

    def list_releases(self):
        return list_pages(self.http, f"{self.api}/releases", "limit=50")

    def find_release(self, tag):
        return pick_release(self.list_releases(), tag)

    def refresh(self, release):
        return self.http.call("GET", f"{self.api}/releases/{release['id']}")

    def exists(self, release):
        # A release Forgejo's API deleted reads as 404, though the database
        # keeps it as a tag-less "tag" row (see docs/ci.md, Preflight).
        return self.http.call("GET", f"{self.api}/releases/{release['id']}", ok404=True) is not None

    def create_draft(self, tag, name, notes, commit, prerelease):
        body = {"tag_name": tag, "target_commitish": commit, "name": name, "body": notes,
                "draft": True, "prerelease": prerelease}
        return self.http.call("POST", f"{self.api}/releases", body, retry=False)

    def raw_assets(self, release):
        return release.get("assets") or []

    def assets(self, release):
        """Forgejo stores an asset only once its upload has completed. It allows
        several assets of one name; the release logic deletes such copies."""
        return {a["name"]: a for a in self.raw_assets(release)}

    def drop_incomplete(self, release):
        return []

    def upload(self, release, path):
        body, ctype = multipart("attachment", path.name, path.read_bytes())
        url = f"{self.api}/releases/{release['id']}/assets?name={urllib.parse.quote(path.name)}"
        self.http.call("POST", url, body, content_type=ctype, retry=False)

    def delete_asset(self, release, item):
        self.http.call("DELETE", f"{self.api}/releases/{release['id']}/assets/{item['id']}", ok404=True)

    def delete_release(self, release):
        self.http.call("DELETE", f"{self.api}/releases/{release['id']}", ok404=True)

    def tag_exists(self, tag):
        """From the repository's tag list, which Forgejo reads from git."""
        return any(t.get("name") == tag for t in list_pages(self.http, f"{self.api}/tags", "limit=50"))

    def download(self, release, item):
        raise ReleaseError("the Forgejo job token can't download release assets")

    def asset_digest(self, release, item):
        raise ReleaseError("the Forgejo job token can't download release assets")

    def publish_release(self, release):
        # Forgejo's API has no make_latest: releases/latest is the newest
        # published non-prerelease by creation date (docs/ci.md).
        return self.http.call("PATCH", f"{self.api}/releases/{release['id']}", {"draft": False})


class GitHub:
    label = "GitHub"
    can_read_assets = True
    # A publish needs the smoke-tested draft (#951); see publish().
    staged_only = True
    API = "https://api.github.com"
    UPLOADS = "https://uploads.github.com"
    published_hint = (
        "GitHub releases in this repository are immutable once published: assets can't be added,"
        " replaced or deleted, and the tag can't be used for another release. This workflow"
        " won't touch it. Release a new version instead."
    )

    def __init__(self, repo, token=None):
        self.repo = repo
        self.api = f"{self.API}/repos/{repo}"
        self.http = Http(f"Bearer {token}" if token else None, {
            "Accept": "application/vnd.github+json", "X-GitHub-Api-Version": "2022-11-28"})

    def tag_commit(self, tag):
        ref = self.http.call("GET", f"{self.api}/git/ref/tags/{urllib.parse.quote(tag)}", ok404=True)
        if ref is None:
            return None
        obj = ref["object"]
        while obj["type"] == "tag":
            obj = self.http.call("GET", f"{self.api}/git/tags/{obj['sha']}")["object"]
        return obj["sha"]

    def list_releases(self):
        return list_pages(self.http, f"{self.api}/releases", "per_page=100")

    def find_release(self, tag):
        # /releases/tags/{tag} never returns a draft.
        return pick_release(self.list_releases(), tag)

    def refresh(self, release):
        return self.http.call("GET", f"{self.api}/releases/{release['id']}")

    def exists(self, release):
        return self.http.call("GET", f"{self.api}/releases/{release['id']}", ok404=True) is not None

    def create_draft(self, tag, name, notes, commit, prerelease):
        body = {"tag_name": tag, "target_commitish": commit, "name": name, "body": notes,
                "draft": True, "prerelease": prerelease}
        return self.http.call("POST", f"{self.api}/releases", body, retry=False)

    def raw_assets(self, release):
        return release.get("assets") or []

    def assets(self, release):
        return {a["name"]: a for a in self.raw_assets(release) if a.get("state") == "uploaded"}

    def drop_incomplete(self, release):
        """Delete what interrupted uploads left behind, so the assets can be sent again."""
        dropped = []
        for item in self.raw_assets(release):
            if item.get("state") != "uploaded":
                self.http.call("DELETE", f"{self.api}/releases/assets/{item['id']}", ok404=True)
                dropped.append(item["name"])
        return dropped

    def upload(self, release, path):
        url = f"{self.UPLOADS}/repos/{self.repo}/releases/{release['id']}/assets?name={urllib.parse.quote(path.name)}"
        self.http.call("POST", url, path.read_bytes(), content_type="application/octet-stream", retry=False)

    def delete_asset(self, release, item):
        self.http.call("DELETE", f"{self.api}/releases/assets/{item['id']}", ok404=True)

    def delete_release(self, release):
        self.http.call("DELETE", f"{self.api}/releases/{release['id']}", ok404=True)

    def tag_exists(self, tag):
        return self.tag_commit(tag) is not None

    def download(self, release, item):
        # browser_download_url doesn't serve a draft's assets. The API URL
        # does, with the token, and redirects to storage, which must not get it.
        return checked_download(self.http, item["url"], item["size"], accept="application/octet-stream")

    def asset_digest(self, release, item):
        return reported_digest(item) or sha256_bytes(self.download(release, item))

    def publish_release(self, release):
        # "legacy": GitHub picks the latest release by date and version, so a
        # backport published after a newer release doesn't become the latest.
        return self.http.call("PATCH", f"{self.api}/releases/{release['id']}",
                              {"draft": False, "make_latest": "legacy"})


def check_tag(host, tag, commit, timeout, dry_run, interval=20):
    """Wait until GitHub has tag, then check that it points at commit."""
    deadline = time.monotonic() + timeout
    while True:
        found = host.tag_commit(tag)
        if found is not None and found != commit:
            problem = f"GitHub's {tag} points at {found}, not {commit}"
            if not dry_run:
                raise ReleaseError(problem)
            print(f"::warning::{problem}; a real run would stop here")
            return
        if found is not None:
            print(f"GitHub has {tag} at {commit}")
            return
        if dry_run:
            print(f"GitHub has no tag {tag} yet; a real run would wait {timeout} s for the push mirror")
            return
        if time.monotonic() >= deadline:
            raise ReleaseError(f"GitHub still has no tag {tag} after {timeout} s; check the push mirror")
        print(f"waiting for the push mirror to bring {tag} to GitHub")
        time.sleep(interval)


def create_draft(host, tag, notes, commit, title=None, prerelease=None):
    """Create the draft. If the response is lost, look for it before trying again."""
    title = title or f"Rusty BACnet {tag}"
    prerelease = "-" in tag if prerelease is None else prerelease
    for attempt in range(1, 4):
        try:
            return host.create_draft(tag, title, notes, commit, prerelease)
        except HttpFailure as err:
            if not err.uncertain or attempt == 3:
                raise
            print(f"creating the draft failed ({err}); checking whether it exists")
            time.sleep(RETRY_DELAY * attempt)
            found = host.find_release(tag)
            if found is not None:
                return found
    raise AssertionError("unreachable")


def upload(host, release, path, digest):
    """Upload one asset to a draft. After an uncertain failure, or GitHub's
    already_exists, the asset is sent again only if the draft still doesn't
    have a complete copy of this file."""
    for attempt in range(1, 4):
        try:
            host.upload(release, path)
            return
        except HttpFailure as err:
            if not (err.uncertain or err.already_exists) or attempt == 3:
                raise
            print(f"uploading {path.name} failed ({err}); checking the draft before retrying")
            time.sleep(RETRY_DELAY * attempt)
            release = host.refresh(release)
            host.drop_incomplete(release)
            release = host.refresh(release)
            item = host.assets(release).get(path.name)
            if item is None:
                continue
            if host.can_read_assets:
                arrived = host.asset_digest(release, item) == digest
            else:  # Forgejo stores an attachment only once its upload is complete
                arrived = item["size"] == path.stat().st_size
            if arrived:
                print(f"{path.name} arrived after all")
                return
            print(f"the draft's {path.name} differs from this file; replacing it")
            host.delete_asset(release, item)
    raise AssertionError("unreachable")


def local_assets(assets_dir):
    files = sorted(p for p in assets_dir.iterdir() if p.is_file() and p.name != SUMS)
    if not files:
        raise ReleaseError(f"no assets in {assets_dir}")
    return {p.name: sha256(p) for p in files}


def duplicate_names(items):
    counts = collections.Counter(a["name"] for a in items)
    return sorted(name for name, count in counts.items() if count > 1)


def stale_draft(host, release, tag, commit):
    """Why this run can't resume the draft, or None if it can."""
    target = release.get("target_commitish")
    if target == commit:
        return None
    return (f"{host.label} has a draft release {tag} (id {release['id']}) made for {target or 'no commit'},"
            f" not {commit}, so this run won't add to it. Delete that draft, then re-run the release.")


def unwanted(host, release, local, exact=False):
    """[(asset, reason)] for what a resumed draft holds that this run won't publish:
    assets that aren't part of the release, every copy of a duplicated name and, on
    a host that can't checksum assets, everything (this run's copies replace it).
    With exact (the smoke test's staging), also every asset that differs from this
    run's file, so the draft ends up holding exactly the local files."""
    allowed = set(local) | {SUMS}
    raw = sorted(host.raw_assets(release), key=lambda a: (a["name"], a["id"]))
    dupes = set(duplicate_names(raw))
    found = []
    for item in raw:
        if item["name"] not in allowed:
            found.append((item, "it isn't part of this release"))
        elif item["name"] in dupes:
            found.append((item, "the draft has several assets of this name"))
        elif not host.can_read_assets:
            found.append((item, "this job can't checksum it, so this run's copy replaces it"))
        elif exact and item["name"] != SUMS and host.asset_digest(release, item) != local[item["name"]]:
            found.append((item, "it differs from this run's file, which replaces it"))
    return found


def verify_published(host, release, tag, local):
    """Problems with a published release, which this script must never change."""
    problems = [f"several assets are named {name}" for name in duplicate_names(host.raw_assets(release))]
    assets = host.assets(release)
    problems += [f"{name} is missing" for name in sorted(set(local) - set(assets))]
    if SUMS not in assets:
        return problems + [f"{SUMS} is missing"]
    if not host.can_read_assets:
        print(f"note: {host.label} won't serve the assets to this token, so their checksums aren't re-checked")
        return problems
    sums = parse_sums(host.download(release, assets[SUMS]).decode())
    others = set(assets) - {SUMS}
    problems += [f"{SUMS} doesn't list {name}" for name in sorted(others - set(sums))]
    problems += [f"{SUMS} lists {name}, which the release doesn't have" for name in sorted(set(sums) - others)]
    for name in sorted(others & set(sums)):
        if host.asset_digest(release, assets[name]) != sums[name]:
            problems.append(f"{name} doesn't match its {SUMS} entry")
        elif name in local and local[name] != sums[name]:
            print(f"note: the release's {name} is from an earlier build of {tag}")
    return problems


def verify_final(host, release, expected):
    """The last check before publishing, on a fresh copy of the draft: it holds
    exactly the names in expected ({name: (sha256, size)}), once each, every one
    completely uploaded, with the expected digest (or, where the host reports
    none and can't serve the asset, the expected size)."""
    raw = host.raw_assets(release)
    names = [a["name"] for a in raw]
    problems = [f"several assets are named {name}" for name in duplicate_names(raw)]
    problems += [f"{a['name']} is not completely uploaded (state {a['state']})"
                 for a in raw if a.get("state", "uploaded") != "uploaded"]
    problems += [f"{name} is missing" for name in sorted(set(expected) - set(names))]
    problems += [f"{name} isn't part of this release" for name in sorted(set(names) - set(expected))]
    methods = set()
    for item in sorted(raw, key=lambda a: a["name"]):
        if item["name"] not in expected or names.count(item["name"]) > 1:
            continue
        name, (digest, size) = item["name"], expected[item["name"]]
        if item.get("size") != size:
            problems.append(f"{name} is {item.get('size')} bytes, expected {size}")
            continue
        found = reported_digest(item)
        if found is None and host.can_read_assets:
            found = sha256_bytes(host.download(release, item))
            methods.add("downloaded sha256")
        elif found is not None:
            methods.add("reported sha256 digest")
        else:
            methods.add("size only: the host reports no digest and won't serve the asset")
        if found is not None and found != digest:
            problems.append(f"{name} has sha256 {found}, expected {digest}")
    if problems:
        listed = "".join(f"\n  - {p}" for p in problems)
        raise ReleaseError(f"{host.label} draft {release.get('tag_name')} failed the final check, so it stays"
                           f" a draft:{listed}")
    print(f"final check: {len(expected)} assets as expected ({'; '.join(sorted(methods))})")


def probe_download(host, release):
    """Download the smallest asset, to show that the token can read the release."""
    assets = host.assets(release)
    if not assets or not host.can_read_assets:
        return
    item = min(assets.values(), key=lambda a: (a["size"], a["name"]))
    data = host.download(release, item)
    print(f"download check: {item['name']} ({len(data)} bytes) read with the token")
    return item, data


def plan(host, release, tag, commit, local):
    """Dry run against a draft or no release: say what a real run would do."""
    existing = {}
    if release is None:
        print(f"would create draft release {tag} at {commit}")
    else:
        problem = stale_draft(host, release, tag, commit)
        if problem:
            print(f"::warning::{problem} A real run would stop here.")
            return
        print(f"would resume draft release {tag} (id {release['id']}), keeping its notes")
        dropped = unwanted(host, release, local)
        for item, why in dropped:
            print(f"would delete {item['name']}: {why}")
        gone = {item["id"] for item, _ in dropped}
        existing = {a["name"]: a for a in host.assets(release).values() if a["id"] not in gone}
    for name in sorted(local):
        print(f"skip {name}: already on the draft" if name in existing else f"would upload {name}")
    final = (set(existing) - {SUMS}) | set(local)
    print(f"would upload {SUMS} for {len(final)} assets, check them all, then publish the draft")


def publish(host, tag, notes, assets_dir, commit, dry_run, staged=None):
    """Publish the release for tag.

    On GitHub (host.staged_only), a publish needs staged, the (release id,
    SHA256SUMS sha256) of the draft the smoke test ran against (#951): the
    release must be that draft, holding exactly this run's files and that
    SHA256SUMS, and the only write is the publish. Without it nothing happens.
    On Forgejo the draft is made, filled, checked and published here."""
    if not dry_run and staged is None and host.staged_only:
        raise ReleaseError(f"{host.label} publishes only the draft the smoke test ran against, and no staged draft"
                           " was given (--staged-release, --staged-sums), so nothing is published")
    local = local_assets(assets_dir)
    release = host.find_release(tag)
    if staged is not None:
        staged_id, staged_sums = staged
        if release is None or str(release["id"]) != str(staged_id):
            found = "none" if release is None else f"id {release['id']}"
            raise ReleaseError(f"{host.label}'s release {tag} ({found}) isn't the draft the smoke test ran against"
                               f" (id {staged_id}), so it isn't published. Delete the stray release, then re-run"
                               " the release.")

    if release is not None and not release.get("draft"):
        print(f"{host.label} release {tag} is already published; checking it, read only")
        problems = verify_published(host, release, tag, local)
        if dry_run:
            probe_download(host, release)
        if not problems:
            print(f"{host.label} release {tag} is complete; nothing to do")
            return
        listed = "".join(f"\n  - {p}" for p in problems)
        message = f"{host.label} release {tag} is published but incomplete:{listed}\n{host.published_hint}"
        if not dry_run:
            raise ReleaseError(message)
        print(f"::warning::{message}\nA real run would stop here.")
        return

    if dry_run:
        plan(host, release, tag, commit, local)
        if release is not None:
            probe_download(host, release)
        return

    if staged is not None:
        print(f"publishing the draft the smoke test ran against (id {staged_id}), unchanged")
        data = sums_text(local).encode()
        if sha256_bytes(data) != staged_sums:
            raise ReleaseError(f"this run's files aren't the ones the smoke test ran against: their {SUMS} has"
                               f" sha256 {sha256_bytes(data)}, the smoke test's {staged_sums}")
        expected = {name: (digest, (assets_dir / name).stat().st_size) for name, digest in local.items()}
        expected[SUMS] = (staged_sums, len(data))
        verify_final(host, host.refresh(release), expected)
        print(f"publishing {tag}")
        release = host.publish_release(release)
        if release.get("draft"):
            raise ReleaseError(f"{host.label} still shows {tag} as a draft after publishing it")
        print(f"done: the smoke-tested draft is public as {tag}")
        return

    # Forgejo's own draft: GitHub's was staged and smoke-tested before this.
    if release is None:
        print(f"creating draft release {tag} at {commit}")
        release = create_draft(host, tag, notes, commit)
    else:
        problem = stale_draft(host, release, tag, commit)
        if problem:
            raise ReleaseError(problem)
        print(f"resuming draft release {tag} (id {release['id']}); keeping its notes")
    uploaded, expected = fill_draft(host, release, tag, assets_dir, local)
    verify_final(host, host.refresh(release), expected)
    print(f"publishing {tag}")
    release = host.publish_release(release)
    if release.get("draft"):
        raise ReleaseError(f"{host.label} still shows {tag} as a draft after publishing it")
    print(f"done: {len(uploaded)} assets uploaded, {len(local) - len(uploaded)} already there; {tag} is public")


def fill_draft(host, release, tag, assets_dir, local, exact=False):
    """Upload the missing assets, then SHA256SUMS over the final set. Returns
    ({name: sha256} of the assets this run uploaded, {name: (sha256, size)} of
    everything the draft must now hold, SHA256SUMS included). With exact, an
    asset that differs from this run's file is replaced, not kept."""
    for name in host.drop_incomplete(release):
        print(f"deleted the incomplete upload of {name}")
    for item, why in unwanted(host, host.refresh(release), local, exact):
        print(f"delete {item['name']}: {why}")
        host.delete_asset(release, item)
    existing = host.assets(host.refresh(release))
    uploaded = {}
    for name in sorted(local):
        if name in existing:
            print(f"skip {name}: already on the draft")
            continue
        print(f"upload {name} ({(assets_dir / name).stat().st_size} bytes)")
        upload(host, release, assets_dir / name, local[name])
        uploaded[name] = local[name]

    final = host.assets(host.refresh(release))
    if set(local) - set(final):
        raise ReleaseError(f"the draft lacks {sorted(set(local) - set(final))} after uploading")
    expected = {}
    for name, item in sorted(final.items()):
        if name == SUMS:
            continue
        if name in uploaded:
            expected[name] = (uploaded[name], (assets_dir / name).stat().st_size)
            continue
        expected[name] = (host.asset_digest(release, item), item["size"])
        if expected[name][0] != local[name]:
            print(f"note: the draft's {name} is from an earlier build of {tag}; keeping it")
    expected[SUMS] = upload_sums(host, release, final.get(SUMS), {n: d for n, (d, _) in expected.items()})
    return uploaded, expected


def upload_sums(host, release, current, digests):
    """Put SHA256SUMS for digests on the draft, replacing current (its asset, or
    None). Returns the file's (sha256, size)."""
    data = sums_text(digests).encode()
    expected = (sha256_bytes(data), len(data))
    if current is not None and host.can_read_assets and host.asset_digest(release, current) == expected[0]:
        print(f"skip {SUMS}: up to date")
        return expected
    if current is not None:
        host.delete_asset(release, current)
    print(f"upload {SUMS} ({len(digests)} assets)")
    with tempfile.TemporaryDirectory() as tmp:
        path = Path(tmp, SUMS)
        path.write_bytes(data)
        upload(host, release, path, expected[0])
    return expected


def stage(host, tag, notes, assets_dir, commit, throwaway=None):
    """Put this run's files on a GitHub draft for the smoke test (#951), without
    publishing it. Returns (release, sha256 of its SHA256SUMS).

    A release run uses the draft for tag, which the GitHub copy later publishes
    unchanged: created at commit if there is none, otherwise resumed (a draft for
    another commit stops the run) and made to hold exactly this run's files, so
    the smoke test runs what PyPI and both releases get. A release that is
    already published is only checked, and its files are smoke-tested. A dry run
    passes throwaway, a release-smoke-* name: a draft of that name is created
    instead (one left by an earlier attempt of the run is deleted first) and
    release_smoke.py deletes it after the smoke test.
    """
    local = local_assets(assets_dir)
    if throwaway is not None:
        if not throwaway.startswith(SMOKE_PREFIX):
            raise ReleaseError(f"refusing to use {throwaway} for a throwaway draft; it must start with {SMOKE_PREFIX}")
        left = [r for r in host.list_releases() if r.get("tag_name") == throwaway]
        if left:
            remove_draft(host, throwaway, left, "smoke test")
        print(f"creating throwaway draft {throwaway} at {commit}")
        release = create_draft(host, throwaway, f"Temporary draft for a release dry run's smoke test ({throwaway});"
                               " the run deletes it again. Safe to delete.", commit,
                               title=f"Release smoke test {throwaway}", prerelease=True)
    else:
        release = host.find_release(tag)
        if release is not None and not release.get("draft"):
            print(f"{host.label} release {tag} is already published; smoke-testing its files")
            problems = verify_published(host, release, tag, local)
            if problems:
                listed = "".join(f"\n  - {p}" for p in problems)
                raise ReleaseError(f"{host.label} release {tag} is published but incomplete:{listed}\n"
                                   f"{host.published_hint}")
            return release, host.asset_digest(release, host.assets(release)[SUMS])
        if release is None:
            print(f"creating draft release {tag} at {commit}")
            release = create_draft(host, tag, notes, commit)
        elif problem := stale_draft(host, release, tag, commit):
            raise ReleaseError(problem)
        else:
            print(f"resuming draft release {tag} (id {release['id']}); keeping its notes")
    _, expected = fill_draft(host, release, release["tag_name"], assets_dir, local, exact=True)
    verify_final(host, host.refresh(release), expected)
    print(f"staged: {host.label} draft {release['tag_name']} (id {release['id']}) holds this run's"
          f" {len(local)} files and {SUMS} (sha256 {expected[SUMS][0]})")
    return release, expected[SUMS][0]


def preflight(host, tag, commit, probe, read_only, tags=None, wait_tag=0):
    """Check, before anything is built, that the release can be published.

    tags (GitHub, anonymous) has the tag checked first. host is None for GitHub
    without a token, which only a read-only run allows. Unless read_only, ends
    with write_check(host, probe, commit).
    """
    if tags is not None:
        check_tag(tags, tag, commit, wait_tag, read_only, interval=30)
    if host is None:
        print("::notice::GH_RELEASE_TOKEN isn't set, so the preflight's GitHub token checks are skipped")
        return
    releases = host.list_releases()
    print(f"{host.label} lists {len(releases)} releases to this token")
    release = pick_release(releases, tag)
    if release is None:
        print(f"{host.label} has no release {tag} yet; the publish job will create it as a draft")
    elif not release.get("draft"):
        print(f"{host.label} release {tag} is already published; the publish job will only check it")
    elif problem := stale_draft(host, release, tag, commit):
        if not read_only:
            raise ReleaseError(problem)
        print(f"::warning::{problem} A real run would stop here.")
    else:
        print(f"{host.label} has a draft release {tag} for {commit}; the publish job will resume it")
    stale = sorted(r["tag_name"] for r in releases if str(r.get("tag_name")).startswith((PROBE_PREFIX, SMOKE_PREFIX)))
    if stale:
        print(f"::warning::{host.label} has preflight or smoke test drafts of other runs: {', '.join(stale)}."
              " Unless such a run is still going, it couldn't delete its draft; delete it by hand.")
    if read_only:
        print(f"read only: the {host.label} write check runs only when publishing")
        return
    write_check(host, probe, commit)
    print(f"{host.label} preflight passed")


def write_check(host, name, commit):
    """Make a draft release called name at commit, check that the release list
    shows it, upload PROBE_ASSETS and check them as the final check would, then
    delete the draft whatever happened, and check that no release or tag called
    name is left."""
    if not name.startswith(PROBE_PREFIX):
        raise ReleaseError(f"refusing to use {name} for the write check; it must start with {PROBE_PREFIX}")
    print(f"write check: draft release {name} at {commit}")
    made = []
    passed = False
    try:
        release = create_draft(host, name, f"Temporary draft from the release preflight ({name}); it deletes"
                               " it again. Safe to delete.", commit, title=f"Release preflight {name}",
                               prerelease=True)
        made.append(release)
        for attempt in range(1, 4):
            listed = host.find_release(name)
            if listed is not None or attempt == 3:
                break
            time.sleep(RETRY_DELAY * attempt)
        if listed is None or listed["id"] != release["id"]:
            raise ReleaseError(f"{host.label}'s release list doesn't show the draft just created, so the token"
                               " can't see drafts and a run couldn't resume a release")
        expected = {}
        with tempfile.TemporaryDirectory() as tmp:
            for asset, data in sorted(PROBE_ASSETS.items()):
                path = Path(tmp, asset)
                path.write_bytes(data)
                print(f"write check: upload {asset} ({len(data)} bytes)")
                upload(host, release, path, sha256_bytes(data))
                expected[asset] = (sha256_bytes(data), len(data))
        fresh = host.refresh(release)
        verify_final(host, fresh, expected)
        if host.can_read_assets:
            item, data = probe_download(host, fresh)
            if data != PROBE_ASSETS[item["name"]]:
                raise ReleaseError(f"downloading the draft's {item['name']} gave other bytes than were uploaded")
        passed = True
    finally:
        try:
            remove_draft(host, name, made, "write check")
        except ReleaseError as err:
            message = (f"the preflight's draft release {name} may still be on {host.label}: {err}."
                       " Delete it by hand.")
            if passed:
                raise ReleaseError(message) from err
            print(f"::error::{message}", file=sys.stderr)  # the check's own failure follows


def remove_draft(host, name, made, label):
    """Delete a disposable draft (the write check's, or a dry run's smoke test
    draft): those in made, by id, and any release listed as name (a create whose
    response was lost). Then check that none is left and that the host has no
    tag name. label prefixes the messages. It deletes only drafts, and only
    those named like the preflight's or the smoke test's."""
    if not name.startswith((PROBE_PREFIX, SMOKE_PREFIX)):
        raise ReleaseError(f"refusing to delete release {name}: only {PROBE_PREFIX}* and {SMOKE_PREFIX}* drafts"
                           " are disposable")

    def delete(release):
        if not release.get("draft"):
            raise ReleaseError(f"refusing to delete release {name} (id {release['id']}): it isn't a draft")
        host.delete_release(release)
        print(f"{label}: deleted draft {name} (id {release['id']})")

    try:
        for release in made:
            delete(release)
        for attempt in range(1, 5):
            left = [r for r in host.list_releases() if r.get("tag_name") == name]
            left += [r for r in made if host.exists(r) and r["id"] not in {x["id"] for x in left}]
            if not left:
                break
            if attempt == 4:
                ids = ", ".join(str(r["id"]) for r in left)
                raise ReleaseError(f"{host.label} still has release {name} (id {ids}) after deleting it")
            time.sleep(RETRY_DELAY * (attempt - 1))
            for release in left:
                delete(release)
        if host.tag_exists(name):
            raise ReleaseError(f"{host.label} now has a tag {name}, though a draft shouldn't create one;"
                               " delete that tag by hand too")
    except HttpFailure as err:
        raise ReleaseError(f"couldn't check that it's gone ({err})") from err
    print(f"{label}: no release or tag {name} is left")


def require_env(name, hint):
    value = os.environ.get(name, "")
    if not value:
        raise ReleaseError(f"{name} is not set. {hint}")
    return value


TOKEN_HINT = ("Add it as a Forgejo repository secret: a fine-grained GitHub token for"
              f" {GITHUB_REPO} with Contents read and write, and Actions read and write for the smoke"
              " test. Then re-run the release.")


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("host", choices=["forgejo", "github"])
    parser.add_argument("--tag", required=True)
    parser.add_argument("--commit", required=True, help="the commit the release is for")
    parser.add_argument("--notes", type=Path, help="the release notes (not with --preflight)")
    parser.add_argument("--assets", type=Path, help="the directory of assets (not with --preflight)")
    parser.add_argument("--wait-tag", type=int, default=0, help="github: seconds to wait for the tag")
    parser.add_argument("--preflight", action="store_true",
                        help="check that the release can be published; with --dry-run, read only")
    parser.add_argument("--dry-run", action="store_true", help="read only; print what would change")
    parser.add_argument("--staged-release", help="github: publish only this draft, the smoke-tested one (#951)")
    parser.add_argument("--staged-sums", help="github: the sha256 of the smoke-tested draft's SHA256SUMS")
    args = parser.parse_args(argv)
    if not args.preflight and (args.notes is None or args.assets is None):
        parser.error("--notes and --assets are required, except with --preflight")
    # A GitHub publish only ever publishes the smoke-tested draft (#951), so it
    # fails closed: both values must be given and non-empty. Other modes take none.
    staged = None
    github_publish = args.host == "github" and not (args.preflight or args.dry_run)
    if github_publish:
        if not (args.staged_release and args.staged_sums):
            parser.error("a github publish needs --staged-release and --staged-sums, both non-empty: the draft the"
                         " smoke test ran against (release_smoke.py's outputs)")
        staged = (args.staged_release, args.staged_sums)
    elif args.staged_release is not None or args.staged_sums is not None:
        parser.error("--staged-release and --staged-sums are only for a github publish")
    if hasattr(sys.stdout, "reconfigure"):  # not when tests capture it
        sys.stdout.reconfigure(line_buffering=True)
    try:
        tags = None
        if args.host == "forgejo":
            host = Forgejo(
                require_env("GITHUB_REPOSITORY", "Forgejo Actions sets it."),
                require_env("GITHUB_SERVER_URL", "Forgejo Actions sets it."),
                require_env("FORGEJO_TOKEN", "Pass the job token."),
            )
        else:
            repo = os.environ.get("GITHUB_REPO", GITHUB_REPO)
            token = os.environ.get("GH_RELEASE_TOKEN", "")
            if not (args.preflight and args.dry_run):
                token = require_env("GH_RELEASE_TOKEN", TOKEN_HINT)
            host = GitHub(repo, token) if token else None
            tags = GitHub(repo)  # anonymous: the repository is public
        if args.preflight:
            probe = f"{PROBE_PREFIX}{os.environ.get('GITHUB_RUN_ID') or 'local'}-{secrets.token_hex(4)}"
            preflight(host, args.tag, args.commit, probe, args.dry_run, tags, args.wait_tag)
            return 0
        notes = args.notes.read_text(encoding="utf-8")
        if args.host == "github":
            check_tag(host, args.tag, args.commit, args.wait_tag, args.dry_run)
        if args.dry_run:
            print("dry run: no writes")
        publish(host, args.tag, notes, args.assets, args.commit, args.dry_run, staged)
    except (ReleaseError, OSError) as err:
        if args.preflight:
            print(f"::error::preflight: {err}\nNothing has been built or published. Fix this, then re-run"
                  " the release.", file=sys.stderr)
        else:
            print(f"::error::{err}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
