#!/usr/bin/env python3
"""Publish a Forgejo or GitHub release as a draft, then make it public (#943).

    release_api.py forgejo --tag v0.12.0 --commit SHA --notes notes.md --assets DIR [--dry-run]
    release_api.py github --tag v0.12.0 --commit SHA --notes notes.md --assets DIR \
        [--wait-tag SECONDS] [--dry-run]

GitHub releases in this repository are immutable once published: their assets
can't be added, replaced or deleted, and the tag can't be reused. So a release
is built as a draft and published by the very last call:

1. find the release for the tag in the release list, drafts included (the
   by-tag endpoints don't return drafts); create a draft at --commit if there
   is none;
2. upload the assets the draft doesn't have yet;
3. upload SHA256SUMS, computed over the draft's final asset set;
4. publish the draft.

Safe to re-run. A draft left by an earlier run is resumed with its notes
(Forgejo deletes a run's artifacts when any of its jobs is re-run, so a re-run
always rebuilds). On GitHub, an asset the earlier run uploaded is kept, with
the checksum GitHub reports for it. Forgejo can't serve a private repository's
assets to the job token, so this script can't checksum them; on a resumed
Forgejo draft, this run's files replace whatever is there. A release that is
already published is only checked, never changed: every asset and SHA256SUMS
must be there, and on GitHub each asset must match SHA256SUMS. Forgejo
releases follow the same order, so releases/latest never shows a half-uploaded
release.

--dry-run makes no write at all. It reads the release list, plans the
uploads, checks a published release and, on GitHub, downloads one existing
asset to show that a resume could read the release.

Environment (values are never printed):
- forgejo: FORGEJO_TOKEN, plus GITHUB_SERVER_URL and GITHUB_REPOSITORY, which
  Forgejo Actions sets for every job;
- github: GH_RELEASE_TOKEN, a fine-grained token with Contents read and write
  on GITHUB_REPO (default jscott3201/rusty-bacnet).

For github, --wait-tag polls until the push mirror has the tag, and the tag
must point at --commit.
"""

import argparse
import hashlib
import json
import os
import sys
import tempfile
import time
import urllib.error
import urllib.parse
import urllib.request
import uuid
from pathlib import Path

SUMS = "SHA256SUMS"
USER_AGENT = "rusty-bacnet-release (+https://github.com/jscott3201/rusty-bacnet)"
RETRY_DELAY = 5  # seconds, times the attempt number; tests set it to 0


class ReleaseError(Exception):
    """A condition the release can't safely continue past."""


class HttpFailure(ReleaseError):
    """A request failed. code is the HTTP status, or None if no response came back."""

    def __init__(self, message, code=None):
        super().__init__(message)
        self.code = code

    @property
    def uncertain(self):
        """True if the server may have carried out the request anyway."""
        return self.code is None or self.code >= 500


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


class Http:
    """A minimal client. The token only ever goes into an unredirected header,
    so a redirect (to release storage, or to a sign-in page) never carries it."""

    def __init__(self, auth_header, headers=None):
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
                failure = HttpFailure(f"{where} returned HTTP {err.code}: {detail}", err.code)
            except OSError as err:  # URLError, timeouts, resets
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


def list_releases(http, url, page_size):
    """Every release, drafts included when the token can write. Stops at an empty page."""
    found = []
    for page in range(1, 51):
        batch = http.call("GET", f"{url}{'&' if '?' in url else '?'}page={page}&{page_size}")
        if not batch:
            return found
        found += batch
    raise ReleaseError(f"{url} has more than 50 pages of releases")


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
    published_hint = (
        "This workflow never changes a published release. Fix it on Forgejo by hand, or delete"
        " the release so that the next run builds it again as a draft."
    )

    def __init__(self, repo, server, token):
        self.repo = repo
        self.api = f"{server}/api/v1/repos/{repo}"
        self.http = Http(f"token {token}", {"Accept": "application/json"})

    def find_release(self, tag):
        return pick_release(list_releases(self.http, f"{self.api}/releases", "limit=50"), tag)

    def refresh(self, release):
        return self.http.call("GET", f"{self.api}/releases/{release['id']}")

    def create_draft(self, tag, name, notes, commit, prerelease):
        body = {"tag_name": tag, "target_commitish": commit, "name": name, "body": notes,
                "draft": True, "prerelease": prerelease}
        return self.http.call("POST", f"{self.api}/releases", body, retry=False)

    def assets(self, release):
        """Forgejo stores an asset only once its upload has completed."""
        return {a["name"]: a for a in release.get("assets") or []}

    def drop_incomplete(self, release):
        return []

    def upload(self, release, path):
        body, ctype = multipart("attachment", path.name, path.read_bytes())
        url = f"{self.api}/releases/{release['id']}/assets?name={urllib.parse.quote(path.name)}"
        self.http.call("POST", url, body, content_type=ctype, retry=False)

    def delete_asset(self, release, item):
        self.http.call("DELETE", f"{self.api}/releases/{release['id']}/assets/{item['id']}")

    def download(self, release, item):
        raise ReleaseError("the Forgejo job token can't download release assets")

    def asset_digest(self, release, item):
        raise ReleaseError("the Forgejo job token can't download release assets")

    def publish_release(self, release):
        return self.http.call("PATCH", f"{self.api}/releases/{release['id']}", {"draft": False})


class GitHub:
    label = "GitHub"
    can_read_assets = True
    API = "https://api.github.com"
    UPLOADS = "https://uploads.github.com"
    published_hint = (
        "GitHub releases in this repository are immutable once published: assets can't be added,"
        " replaced or deleted, and the tag can't be used for another release. This workflow"
        " won't touch it. Release a new version instead."
    )

    def __init__(self, repo, token):
        self.repo = repo
        self.api = f"{self.API}/repos/{repo}"
        self.http = Http(f"Bearer {token}", {
            "Accept": "application/vnd.github+json", "X-GitHub-Api-Version": "2022-11-28"})

    def tag_commit(self, tag):
        ref = self.http.call("GET", f"{self.api}/git/ref/tags/{urllib.parse.quote(tag)}", ok404=True)
        if ref is None:
            return None
        obj = ref["object"]
        while obj["type"] == "tag":
            obj = self.http.call("GET", f"{self.api}/git/tags/{obj['sha']}")["object"]
        return obj["sha"]

    def find_release(self, tag):
        # /releases/tags/{tag} never returns a draft.
        return pick_release(list_releases(self.http, f"{self.api}/releases", "per_page=100"), tag)

    def refresh(self, release):
        return self.http.call("GET", f"{self.api}/releases/{release['id']}")

    def create_draft(self, tag, name, notes, commit, prerelease):
        body = {"tag_name": tag, "target_commitish": commit, "name": name, "body": notes,
                "draft": True, "prerelease": prerelease}
        return self.http.call("POST", f"{self.api}/releases", body, retry=False)

    def assets(self, release):
        return {a["name"]: a for a in release.get("assets") or [] if a.get("state") == "uploaded"}

    def drop_incomplete(self, release):
        """Delete what interrupted uploads left behind, so the assets can be sent again."""
        dropped = []
        for item in release.get("assets") or []:
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
        digest = item.get("digest") or ""
        if digest.startswith("sha256:"):
            return digest.removeprefix("sha256:")
        return sha256_bytes(self.download(release, item))

    def publish_release(self, release):
        return self.http.call("PATCH", f"{self.api}/releases/{release['id']}", {"draft": False})


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


def create_draft(host, tag, notes, commit):
    """Create the draft. If the response is lost, look for it before trying again."""
    for attempt in range(1, 4):
        try:
            return host.create_draft(tag, f"Rusty BACnet {tag}", notes, commit, prerelease="-" in tag)
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
    """Upload one asset to a draft. After an uncertain failure, the asset is sent
    again only if the draft still doesn't have a complete copy of this file."""
    for attempt in range(1, 4):
        try:
            host.upload(release, path)
            return
        except HttpFailure as err:
            if not err.uncertain or attempt == 3:
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


def verify_published(host, release, tag, local):
    """Problems with a published release, which this script must never change."""
    problems = []
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


def probe_download(host, release):
    """Dry run: download the smallest asset, to show that a resume could read the release."""
    assets = host.assets(release)
    if not assets or not host.can_read_assets:
        return
    item = min(assets.values(), key=lambda a: (a["size"], a["name"]))
    data = host.download(release, item)
    print(f"download check: {item['name']} ({len(data)} bytes) read with the token")


def plan(host, release, tag, commit, local):
    """Dry run against a draft or no release: say what a real run would do."""
    existing = host.assets(release) if release else {}
    if release is None:
        print(f"would create draft release {tag} at {commit}")
    else:
        print(f"would resume draft release {tag} (id {release['id']}), keeping its notes")
        if not host.can_read_assets:
            for name in sorted(existing):
                print(f"would delete {name}, which this run's copy replaces")
            existing = {}
    for name in sorted(local):
        print(f"skip {name}: already on the draft" if name in existing else f"would upload {name}")
    final = (set(existing) - {SUMS}) | set(local)
    print(f"would upload {SUMS} for {len(final)} assets, then publish the draft")


def publish(host, tag, notes, assets_dir, commit, dry_run):
    local = local_assets(assets_dir)
    release = host.find_release(tag)

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

    if release is None:
        print(f"creating draft release {tag} at {commit}")
        release = create_draft(host, tag, notes, commit)
    else:
        print(f"resuming draft release {tag} (id {release['id']}); keeping its notes")
    uploaded = fill_draft(host, release, tag, assets_dir, local)
    print(f"publishing {tag}")
    release = host.publish_release(release)
    if release.get("draft"):
        raise ReleaseError(f"{host.label} still shows {tag} as a draft after publishing it")
    print(f"done: {len(uploaded)} assets uploaded, {len(local) - len(uploaded)} already there; {tag} is public")


def fill_draft(host, release, tag, assets_dir, local):
    """Upload the missing assets, then SHA256SUMS over the final set. Returns
    {name: sha256} of the assets this run uploaded."""
    for name in host.drop_incomplete(release):
        print(f"deleted the incomplete upload of {name}")
    existing = host.assets(host.refresh(release))
    if not host.can_read_assets:
        for name, item in sorted(existing.items()):
            print(f"delete {name}: this job can't checksum it, so this run's copy replaces it")
            host.delete_asset(release, item)
        existing = {}
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
    digests = {}
    for name, item in sorted(final.items()):
        if name == SUMS:
            continue
        digests[name] = uploaded.get(name) or host.asset_digest(release, item)
        if name in local and digests[name] != local[name]:
            print(f"note: the draft's {name} is from an earlier build of {tag}; keeping it")
    upload_sums(host, release, final.get(SUMS), digests)

    have = set(host.assets(host.refresh(release)))
    want = set(digests) | {SUMS}
    if have != want:
        raise ReleaseError(f"the draft holds {sorted(have)}, not the expected {sorted(want)}")
    return uploaded


def upload_sums(host, release, current, digests):
    """Put SHA256SUMS for digests on the draft, replacing current (its asset, or None)."""
    text = sums_text(digests)
    digest = sha256_bytes(text.encode())
    if current is not None and host.can_read_assets and host.asset_digest(release, current) == digest:
        print(f"skip {SUMS}: up to date")
        return
    if current is not None:
        host.delete_asset(release, current)
    print(f"upload {SUMS} ({len(digests)} assets)")
    with tempfile.TemporaryDirectory() as tmp:
        path = Path(tmp, SUMS)
        path.write_text(text, encoding="utf-8")
        upload(host, release, path, digest)


def require_env(name, hint):
    value = os.environ.get(name, "")
    if not value:
        raise ReleaseError(f"{name} is not set. {hint}")
    return value


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("host", choices=["forgejo", "github"])
    parser.add_argument("--tag", required=True)
    parser.add_argument("--commit", required=True, help="the commit the release is for")
    parser.add_argument("--notes", required=True, type=Path)
    parser.add_argument("--assets", required=True, type=Path)
    parser.add_argument("--wait-tag", type=int, default=0, help="github: seconds to wait for the tag")
    parser.add_argument("--dry-run", action="store_true", help="read only; print what would change")
    args = parser.parse_args(argv)
    if hasattr(sys.stdout, "reconfigure"):  # not when tests capture it
        sys.stdout.reconfigure(line_buffering=True)
    try:
        notes = args.notes.read_text(encoding="utf-8")
        if args.host == "forgejo":
            host = Forgejo(
                require_env("GITHUB_REPOSITORY", "Forgejo Actions sets it."),
                require_env("GITHUB_SERVER_URL", "Forgejo Actions sets it."),
                require_env("FORGEJO_TOKEN", "Pass the job token."),
            )
        else:
            token = require_env(
                "GH_RELEASE_TOKEN",
                "Add it as a Forgejo repository secret: a fine-grained GitHub token for"
                " jscott3201/rusty-bacnet with Contents read and write. Then re-run the release.",
            )
            host = GitHub(os.environ.get("GITHUB_REPO", "jscott3201/rusty-bacnet"), token)
            check_tag(host, args.tag, args.commit, args.wait_tag, args.dry_run)
        if args.dry_run:
            print("dry run: no writes")
        publish(host, args.tag, notes, args.assets, args.commit, args.dry_run)
    except (ReleaseError, OSError) as err:
        print(f"::error::{err}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
