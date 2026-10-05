#!/usr/bin/env python3
"""Stage, check and publish the GitHub release for a tag (#943, #1472).

    release_api.py stage --tag v0.12.0 --commit SHA --notes notes.md --assets DIR
    release_api.py publish --tag v0.12.0 --commit SHA --assets DIR \
        --staged-release ID --staged-sums SHA256
    release_api.py plan --tag v0.12.0 --commit SHA --assets DIR

GitHub releases in this repository are immutable once published: their assets
can't be added, replaced or deleted, and the tag can't be used again. So the
release workflow stages the release as a draft before it publishes anything
anywhere, and makes the draft public last, after crates.io and PyPI.

stage, the GitHub draft job:
1. check that the tag exists and points at --commit;
2. find the release for the tag in the release list, drafts included (the
   by-tag endpoint doesn't return drafts), and create a draft at --commit if
   there is none. A draft made for another commit stops the run. A release
   that is already published is only checked (see below);
3. make the draft hold exactly the files in --assets: delete what the
   interrupted uploads left, every asset that isn't one of those files, every
   copy of a name that appears twice and every asset that differs from this
   run's file, then upload what's missing;
4. upload SHA256SUMS for those files, replacing an outdated one;
5. run the final check.
It writes release_id and sums_sha256 (the sha256 of SHA256SUMS) to
GITHUB_OUTPUT.

publish, the GitHub release job: publishes that very draft, unchanged. The
tag's release must be the staged draft, this run's files must give the staged
SHA256SUMS, and the draft must pass the final check again; the publish is the
only write. A publish without both staged values does nothing.

plan, for dry runs: read only. It says what stage would do, checks a
published release and downloads its smallest asset. GitHub lists drafts only
to a token that can write, so a read-only plan can't see one.

The final check is the last before the irreversible publish: the draft, read
afresh, must hold exactly the expected names, once each, all completely
uploaded, each with the expected size and with GitHub's reported sha256
digest equal to the expected one (an asset without a digest is downloaded and
hashed). A published release is never changed: every asset and SHA256SUMS
must be on it and match SHA256SUMS, or the run fails with an explanation.

Safe to re-run: a draft left by an earlier attempt is resumed, keeping its
notes, and assets it already holds with this run's bytes aren't sent again.

Environment (values are never printed): GITHUB_TOKEN, which needs Contents
write for stage and publish (GitHub shows drafts only to a token that can
write); GITHUB_REPOSITORY, which Actions sets (default
jscott3201/rusty-bacnet).
"""

import argparse
import collections
import hashlib
import json
import os
import sys
import tempfile
import time
import urllib.error
import urllib.parse
import urllib.request
from http.client import HTTPException
from pathlib import Path

SUMS = "SHA256SUMS"
USER_AGENT = "rusty-bacnet-release (+https://github.com/jscott3201/rusty-bacnet)"
RETRY_DELAY = 5  # seconds, times the attempt number; tests set it to 0
GITHUB_REPO = "jscott3201/rusty-bacnet"


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
    """The sha256 GitHub reports for an asset (its `digest`), or None."""
    digest = item.get("digest") or ""
    return digest.removeprefix("sha256:") if digest.startswith("sha256:") else None


def write_outputs(**values):
    """Append key=value lines to GITHUB_OUTPUT, when Actions sets it."""
    path = os.environ.get("GITHUB_OUTPUT")
    if path:
        with open(path, "a", encoding="utf-8") as out:
            for key, value in values.items():
                out.write(f"{key}={value}\n")


class Http:
    """A minimal client. The token only ever goes into an unredirected header,
    so a redirect (to release storage) never carries it. Without auth_header,
    requests are anonymous."""

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


class GitHub:
    """The repository's releases through GitHub's REST API."""

    label = "GitHub"
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


def check_tag(host, tag, commit, dry_run=False):
    """The tag must exist and point at commit; a dry run only warns."""
    found = host.tag_commit(tag)
    if found == commit:
        print(f"{host.label} has {tag} at {commit}")
        return
    problem = (f"{host.label} has no tag {tag}" if found is None
               else f"{host.label}'s {tag} points at {found}, not {commit}")
    if not dry_run:
        raise ReleaseError(problem)
    print(f"::warning::{problem}; a release would stop here")


def create_draft(host, tag, notes, commit):
    """Create the draft. If the response is lost, look for it before trying again."""
    for attempt in range(1, 4):
        try:
            return host.create_draft(tag, f"Rusty BACnet {tag}", notes, commit, "-" in tag)
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
            if host.asset_digest(release, item) == digest:
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


def unwanted(host, release, local):
    """[(asset, reason)] for what a draft holds that this run won't publish:
    assets that aren't part of the release, every copy of a duplicated name, and
    every asset that differs from this run's file. SHA256SUMS is left to
    upload_sums."""
    allowed = set(local) | {SUMS}
    raw = sorted(host.raw_assets(release), key=lambda a: (a["name"], a["id"]))
    dupes = set(duplicate_names(raw))
    found = []
    for item in raw:
        if item["name"] not in allowed:
            found.append((item, "it isn't part of this release"))
        elif item["name"] in dupes:
            found.append((item, "the draft has several assets of this name"))
        elif item["name"] != SUMS and host.asset_digest(release, item) != local[item["name"]]:
            found.append((item, "it differs from this run's file, which replaces it"))
    return found


def verify_published(host, release, tag, local):
    """Problems with a published release, which this script must never change."""
    problems = [f"several assets are named {name}" for name in duplicate_names(host.raw_assets(release))]
    assets = host.assets(release)
    problems += [f"{name} is missing" for name in sorted(set(local) - set(assets))]
    if SUMS not in assets:
        return problems + [f"{SUMS} is missing"]
    sums = parse_sums(host.download(release, assets[SUMS]).decode())
    others = set(assets) - {SUMS}
    problems += [f"{SUMS} doesn't list {name}" for name in sorted(others - set(sums))]
    problems += [f"{SUMS} lists {name}, which the release doesn't have" for name in sorted(set(sums) - others)]
    for name in sorted(others & set(sums)):
        if host.asset_digest(release, assets[name]) != sums[name]:
            problems.append(f"{name} doesn't match its {SUMS} entry")
        elif name in local and local[name] != sums[name]:
            print(f"note: the release's {name} is from another build of {tag} than this run's")
    return problems


def published_problems(host, release, tag, local):
    """ReleaseError text for a published release that fails the check, or None."""
    problems = verify_published(host, release, tag, local)
    if not problems:
        return None
    listed = "".join(f"\n  - {p}" for p in problems)
    return f"{host.label} release {tag} is published but incomplete:{listed}\n{host.published_hint}"


def verify_final(host, release, expected):
    """The last check before publishing, on a fresh copy of the draft: it holds
    exactly the names in expected ({name: (sha256, size)}), once each, every one
    completely uploaded, with the expected size and digest."""
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
        if found is None:
            found = sha256_bytes(host.download(release, item))
            methods.add("downloaded sha256")
        else:
            methods.add("reported sha256 digest")
        if found != digest:
            problems.append(f"{name} has sha256 {found}, expected {digest}")
    if problems:
        listed = "".join(f"\n  - {p}" for p in problems)
        raise ReleaseError(f"{host.label} draft {release.get('tag_name')} failed the final check, so it stays"
                           f" a draft:{listed}")
    print(f"final check: {len(expected)} assets as expected ({'; '.join(sorted(methods))})")


def probe_download(host, release):
    """Download the smallest asset, to show that the token can read the release."""
    assets = host.assets(release)
    if not assets:
        return
    item = min(assets.values(), key=lambda a: (a["size"], a["name"]))
    data = host.download(release, item)
    print(f"download check: {item['name']} ({len(data)} bytes) read")


def expected_assets(assets_dir, local):
    """{name: (sha256, size)} for the local files and their SHA256SUMS."""
    data = sums_text(local).encode()
    expected = {name: (digest, (assets_dir / name).stat().st_size) for name, digest in local.items()}
    expected[SUMS] = (sha256_bytes(data), len(data))
    return expected


def fill_draft(host, release, assets_dir, local):
    """Make the draft hold exactly the local files and their SHA256SUMS.
    Returns {name: (sha256, size)} of everything it must now hold."""
    for name in host.drop_incomplete(release):
        print(f"deleted the incomplete upload of {name}")
    for item, why in unwanted(host, host.refresh(release), local):
        print(f"delete {item['name']}: {why}")
        host.delete_asset(release, item)
    existing = host.assets(host.refresh(release))
    for name in sorted(local):
        if name in existing:
            print(f"skip {name}: already on the draft")
            continue
        print(f"upload {name} ({(assets_dir / name).stat().st_size} bytes)")
        upload(host, release, assets_dir / name, local[name])
    final = host.assets(host.refresh(release))
    if set(local) - set(final):
        raise ReleaseError(f"the draft lacks {sorted(set(local) - set(final))} after uploading")
    expected = expected_assets(assets_dir, local)
    upload_sums(host, release, final.get(SUMS), local, expected[SUMS][0])
    return expected


def upload_sums(host, release, current, digests, sums_sha):
    """Put SHA256SUMS for digests on the draft, replacing current (its asset, or None)."""
    if current is not None and host.asset_digest(release, current) == sums_sha:
        print(f"skip {SUMS}: up to date")
        return
    if current is not None:
        host.delete_asset(release, current)
    print(f"upload {SUMS} ({len(digests)} assets)")
    with tempfile.TemporaryDirectory() as tmp:
        path = Path(tmp, SUMS)
        path.write_text(sums_text(digests), encoding="utf-8")
        upload(host, release, path, sums_sha)


def stage(host, tag, notes, assets_dir, commit):
    """Make the draft for tag hold exactly this run's files, without publishing
    it. Returns (release, sha256 of its SHA256SUMS)."""
    local = local_assets(assets_dir)
    release = host.find_release(tag)
    if release is not None and not release.get("draft"):
        print(f"{host.label} release {tag} is already published; checking it, read only")
        problem = published_problems(host, release, tag, local)
        if problem:
            raise ReleaseError(problem)
        print(f"{host.label} release {tag} is complete; the publish job will only check it again")
        return release, host.asset_digest(release, host.assets(release)[SUMS])
    if release is None:
        print(f"creating draft release {tag} at {commit}")
        release = create_draft(host, tag, notes, commit)
    elif problem := stale_draft(host, release, tag, commit):
        raise ReleaseError(problem)
    else:
        print(f"resuming draft release {tag} (id {release['id']}); keeping its notes")
    expected = fill_draft(host, release, assets_dir, local)
    verify_final(host, host.refresh(release), expected)
    print(f"staged: draft {tag} (id {release['id']}) holds this run's {len(local)} files and {SUMS}"
          f" (sha256 {expected[SUMS][0]})")
    return release, expected[SUMS][0]


def publish(host, tag, assets_dir, staged):
    """Publish the draft that stage() made, unchanged. staged is its (release
    id, SHA256SUMS sha256)."""
    staged_id, staged_sums = staged
    local = local_assets(assets_dir)
    release = host.find_release(tag)
    if release is None or str(release["id"]) != str(staged_id):
        found = "none" if release is None else f"id {release['id']}"
        raise ReleaseError(f"{host.label}'s release {tag} ({found}) isn't the draft this run staged (id"
                           f" {staged_id}), so nothing is published. Delete the stray release, then re-run"
                           " the release.")
    if not release.get("draft"):
        print(f"{host.label} release {tag} is already published; checking it, read only")
        problem = published_problems(host, release, tag, local)
        if problem:
            raise ReleaseError(problem)
        print(f"{host.label} release {tag} is complete; nothing to do")
        return
    expected = expected_assets(assets_dir, local)
    if expected[SUMS][0] != staged_sums:
        raise ReleaseError(f"this run's files aren't the ones it staged: their {SUMS} has sha256"
                           f" {expected[SUMS][0]}, the staged one {staged_sums}")
    print(f"publishing the staged draft {tag} (id {staged_id}), unchanged")
    verify_final(host, host.refresh(release), expected)
    release = host.publish_release(release)
    if release.get("draft"):
        raise ReleaseError(f"{host.label} still shows {tag} as a draft after publishing it")
    print(f"done: {tag} is public")


def plan(host, tag, assets_dir, commit):
    """Dry run: say what stage would do, without writing."""
    local = local_assets(assets_dir)
    release = host.find_release(tag)
    if release is not None and not release.get("draft"):
        print(f"{host.label} release {tag} is already published; checking it, read only")
        problem = published_problems(host, release, tag, local)
        print(f"::warning::{problem}\nA release would stop here." if problem else
              f"{host.label} release {tag} is complete; a release would only check it")
        probe_download(host, release)
        return
    existing = {}
    if release is None:
        print(f"would create draft release {tag} at {commit} (GitHub lists drafts only to a token that can"
              " write, so a draft left by an earlier run may not show here)")
    elif problem := stale_draft(host, release, tag, commit):
        print(f"::warning::{problem} A release would stop here.")
        return
    else:
        print(f"would resume draft release {tag} (id {release['id']}), keeping its notes")
        dropped = unwanted(host, release, local)
        for item, why in dropped:
            print(f"would delete {item['name']}: {why}")
        gone = {item["id"] for item, _ in dropped}
        existing = {a["name"]: a for a in host.assets(release).values() if a["id"] not in gone}
        probe_download(host, release)
    for name in sorted(local):
        print(f"skip {name}: already on the draft" if name in existing else f"would upload {name}")
    print(f"would upload {SUMS} for {len(local)} assets and check them all; after crates.io and PyPI, the"
          " GitHub release job would publish the draft")


def require_env(name, hint):
    value = os.environ.get(name, "")
    if not value:
        raise ReleaseError(f"{name} is not set. {hint}")
    return value


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    sub = parser.add_subparsers(dest="command", required=True)
    commands = {
        "stage": sub.add_parser("stage", help="make the tag's draft hold exactly these files"),
        "publish": sub.add_parser("publish", help="publish the staged draft, unchanged"),
        "plan": sub.add_parser("plan", help="read only: what stage would do"),
    }
    for command in commands.values():
        command.add_argument("--tag", required=True)
        command.add_argument("--commit", required=True, help="the commit the release is for")
        command.add_argument("--assets", type=Path, required=True, help="the directory of assets")
    commands["stage"].add_argument("--notes", type=Path, required=True, help="the release notes")
    commands["publish"].add_argument("--staged-release", required=True, help="the staged draft's id")
    commands["publish"].add_argument("--staged-sums", required=True, help="the sha256 of its SHA256SUMS")
    args = parser.parse_args(argv)
    # Fails closed: empty values (an unset job output) publish nothing.
    if args.command == "publish" and not (args.staged_release and args.staged_sums):
        parser.error("publish needs --staged-release and --staged-sums, both non-empty: the GitHub draft"
                     " job's outputs")
    if hasattr(sys.stdout, "reconfigure"):  # not when tests capture it
        sys.stdout.reconfigure(line_buffering=True)
    try:
        repo = os.environ.get("GITHUB_REPOSITORY") or GITHUB_REPO
        if args.command == "plan":
            host = GitHub(repo, os.environ.get("GITHUB_TOKEN") or None)
            print("dry run: no writes")
            check_tag(host, args.tag, args.commit, dry_run=True)
            plan(host, args.tag, args.assets, args.commit)
            return 0
        host = GitHub(repo, require_env("GITHUB_TOKEN", "Pass the job token, with contents: write."))
        check_tag(host, args.tag, args.commit)
        if args.command == "stage":
            release, sums = stage(host, args.tag, args.notes.read_text(encoding="utf-8"), args.assets,
                                  args.commit)
            write_outputs(release_id=release["id"], sums_sha256=sums)
        else:
            publish(host, args.tag, args.assets, (args.staged_release, args.staged_sums))
    except (ReleaseError, OSError) as err:
        print(f"::error::{err}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
