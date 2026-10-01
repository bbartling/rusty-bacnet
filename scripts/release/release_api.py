#!/usr/bin/env python3
"""Create a Forgejo or GitHub release if it's missing and upload missing assets (#943).

    release_api.py forgejo --tag v0.12.0 --notes notes.md --assets DIR [--dry-run]
    release_api.py github --tag v0.12.0 --notes notes.md --assets DIR --commit SHA \
        [--wait-tag SECONDS] [--dry-run]

Safe to re-run. An existing release is reused as it is, notes included, and only
the assets it doesn't have yet are uploaded. SHA256SUMS goes up last and lists
what the release actually holds: an asset a previous run uploaded keeps that
run's checksum, which matters because Forgejo deletes a run's artifacts when any
of its jobs is re-run, so a re-run always rebuilds.

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
import time
import urllib.error
import urllib.parse
import urllib.request
import uuid
from pathlib import Path

SUMS = "SHA256SUMS"
USER_AGENT = "rusty-bacnet-release (+https://github.com/jscott3201/rusty-bacnet)"


class ReleaseError(Exception):
    """A condition the release can't safely continue past."""


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


def release_digests(local, missing, published_sums, remote_digest):
    """The checksum of each asset as the release will hold it.

    local: {name: sha256} of this run's files; missing: the names this run uploads.
    published_sums: the release's SHA256SUMS as {name: sha256}, or None.
    remote_digest(name): downloads and hashes an asset already on the release.
    It is skipped when the published SHA256SUMS already gives this run's digest.
    Returns ({name: sha256}, [names whose release copy differs from this run's file]).
    """
    digests, differs = {}, []
    for name in sorted(local):
        if name in missing:
            digests[name] = local[name]
            continue
        known = (published_sums or {}).get(name)
        digests[name] = known if known == local[name] else remote_digest(name)
        if digests[name] != local[name]:
            differs.append(name)
    return digests, differs


class Api:
    """A minimal JSON client; the token only ever goes into a header."""

    def __init__(self, base, auth_header, extra_headers=None):
        self.base = base.rstrip("/")
        self.headers = {"Authorization": auth_header, "User-Agent": USER_AGENT, **(extra_headers or {})}

    def request(self, method, url, body=None, content_type="application/json", accept_404=False):
        if not url.startswith("https://"):
            url = self.base + url
        data = json.dumps(body).encode() if isinstance(body, dict) else body
        req = urllib.request.Request(url, data=data, method=method, headers=dict(self.headers))
        if data is not None:
            req.add_header("Content-Type", content_type)
        for attempt in range(4):
            try:
                with urllib.request.urlopen(req, timeout=300) as resp:
                    raw = resp.read()
                    return json.loads(raw) if raw and "json" in resp.headers.get("Content-Type", "") else raw
            except urllib.error.HTTPError as err:
                if err.code == 404 and accept_404:
                    return None
                if err.code >= 500 and attempt < 3:
                    time.sleep(5 * (attempt + 1))
                    continue
                detail = err.read().decode(errors="replace")[:500]
                raise ReleaseError(f"{method} {url.split('?')[0]} returned HTTP {err.code}: {detail}") from None
            except urllib.error.URLError as err:
                if attempt < 3:
                    time.sleep(5 * (attempt + 1))
                    continue
                raise ReleaseError(f"{method} {url.split('?')[0]} failed: {err.reason}") from None
        raise AssertionError("unreachable")


def multipart(field, filename, payload):
    boundary = uuid.uuid4().hex
    head = (
        f'--{boundary}\r\nContent-Disposition: form-data; name="{field}"; filename="{filename}"\r\n'
        "Content-Type: application/octet-stream\r\n\r\n"
    ).encode()
    return head + payload + f"\r\n--{boundary}--\r\n".encode(), f"multipart/form-data; boundary={boundary}"


def asset(release, name):
    return next(a for a in release.get("assets") or [] if a["name"] == name)


class Forgejo:
    def __init__(self, repo, server, token):
        self.repo = repo
        self.api = Api(f"{server}/api/v1", f"token {token}")

    def get_release(self, tag):
        return self.api.request("GET", f"/repos/{self.repo}/releases/tags/{urllib.parse.quote(tag)}", accept_404=True)

    def create_release(self, tag, name, notes, prerelease):
        body = {"tag_name": tag, "name": name, "body": notes, "draft": False, "prerelease": prerelease}
        return self.api.request("POST", f"/repos/{self.repo}/releases", body)

    def assets(self, release):
        return {a["name"]: a["size"] for a in release.get("assets") or []}

    def drop_incomplete(self, release):
        """Forgejo stores an asset only once its upload completes."""

    def download(self, release, name):
        return self.api.request("GET", asset(release, name)["browser_download_url"])

    def upload(self, release, path):
        body, ctype = multipart("attachment", path.name, path.read_bytes())
        url = f"/repos/{self.repo}/releases/{release['id']}/assets?name={urllib.parse.quote(path.name)}"
        self.api.request("POST", url, body, content_type=ctype)

    def delete(self, release, name):
        self.api.request("DELETE", f"/repos/{self.repo}/releases/{release['id']}/assets/{asset(release, name)['id']}")


class GitHub:
    API = "https://api.github.com"
    UPLOADS = "https://uploads.github.com"

    def __init__(self, repo, token):
        self.repo = repo
        self.api = Api(self.API, f"Bearer {token}", {
            "Accept": "application/vnd.github+json", "X-GitHub-Api-Version": "2022-11-28"})

    def tag_commit(self, tag):
        ref = self.api.request("GET", f"/repos/{self.repo}/git/ref/tags/{urllib.parse.quote(tag)}", accept_404=True)
        if ref is None:
            return None
        obj = ref["object"]
        while obj["type"] == "tag":
            obj = self.api.request("GET", f"/repos/{self.repo}/git/tags/{obj['sha']}")["object"]
        return obj["sha"]

    def get_release(self, tag):
        return self.api.request("GET", f"/repos/{self.repo}/releases/tags/{urllib.parse.quote(tag)}", accept_404=True)

    def create_release(self, tag, name, notes, prerelease):
        body = {"tag_name": tag, "name": name, "body": notes, "draft": False, "prerelease": prerelease}
        return self.api.request("POST", f"/repos/{self.repo}/releases", body)

    def assets(self, release):
        return {a["name"]: a["size"] for a in release.get("assets") or [] if a.get("state") == "uploaded"}

    def drop_incomplete(self, release):
        """Delete assets an interrupted upload left behind, so they can be sent again."""
        for item in release.get("assets") or []:
            if item.get("state") != "uploaded":
                print(f"deleting incomplete asset {item['name']}")
                self.api.request("DELETE", f"/repos/{self.repo}/releases/assets/{item['id']}")

    def download(self, release, name):
        # The repository is public: browser_download_url needs no token, and its
        # storage redirect must not carry one.
        req = urllib.request.Request(asset(release, name)["browser_download_url"], headers={"User-Agent": USER_AGENT})
        with urllib.request.urlopen(req, timeout=300) as resp:
            return resp.read()

    def upload(self, release, path):
        url = f"{self.UPLOADS}/repos/{self.repo}/releases/{release['id']}/assets?name={urllib.parse.quote(path.name)}"
        self.api.request("POST", url, path.read_bytes(), content_type="application/octet-stream")

    def delete(self, release, name):
        self.api.request("DELETE", f"/repos/{self.repo}/releases/assets/{asset(release, name)['id']}")


def wait_for_tag(host, tag, commit, timeout, interval=20):
    deadline = time.monotonic() + timeout
    while True:
        found = host.tag_commit(tag)
        if found is not None:
            if found != commit:
                raise ReleaseError(f"GitHub's {tag} points at {found}, not {commit}")
            print(f"GitHub has {tag} at {commit}")
            return
        if time.monotonic() >= deadline:
            raise ReleaseError(f"GitHub still has no tag {tag} after {timeout} s; check the push mirror")
        print(f"waiting for the push mirror to bring {tag} to GitHub")
        time.sleep(interval)


def publish(host, tag, notes, assets_dir, dry_run):
    act = "would " if dry_run else ""
    files = sorted(p for p in assets_dir.iterdir() if p.is_file() and p.name != SUMS)
    if not files:
        raise ReleaseError(f"no assets in {assets_dir}")
    local = {p.name: sha256(p) for p in files}

    release = host.get_release(tag)
    if release is not None:
        print(f"release {tag} exists; keeping its notes")
    elif dry_run:
        print(f"would create release {tag}")
        release = {"assets": []}
    else:
        print(f"creating release {tag}")
        release = host.create_release(tag, f"Rusty BACnet {tag}", notes, prerelease="-" in tag)
    existing = host.assets(release)
    if not dry_run:
        host.drop_incomplete(release)

    missing = [name for name in sorted(local) if name not in existing]
    for name in sorted(local):
        if name not in missing:
            print(f"skip {name}: already on the release")
    for name in missing:
        path = assets_dir / name
        print(f"{act}upload {name} ({path.stat().st_size} bytes)")
        if not dry_run:
            host.upload(release, path)

    published = parse_sums(host.download(release, SUMS).decode()) if SUMS in existing else None
    digests, differs = release_digests(
        local, set(missing), published, lambda name: sha256_bytes(host.download(release, name)))
    for name in differs:
        print(f"note: the release's {name} is from an earlier build of {tag}; keeping it")
    text = sums_text(digests)
    if published is not None and sums_text(published) == text:
        print(f"skip {SUMS}: up to date")
    else:
        print(f"{act}{'replace' if published is not None else 'upload'} {SUMS}")
        if not dry_run:
            (assets_dir / SUMS).write_text(text, encoding="utf-8")
            if published is not None:
                host.delete(release, SUMS)
            host.upload(release, assets_dir / SUMS)
    print(f"done: {len(missing)} assets {'to upload' if dry_run else 'uploaded'}, "
          f"{len(local) - len(missing)} already there")


def require_env(name, hint):
    value = os.environ.get(name, "")
    if not value:
        raise ReleaseError(f"{name} is not set. {hint}")
    return value


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("host", choices=["forgejo", "github"])
    parser.add_argument("--tag", required=True)
    parser.add_argument("--notes", required=True, type=Path)
    parser.add_argument("--assets", required=True, type=Path)
    parser.add_argument("--commit", help="github: the commit the tag must point at")
    parser.add_argument("--wait-tag", type=int, default=0, help="github: seconds to wait for the tag")
    parser.add_argument("--dry-run", action="store_true", help="read only; print what would change")
    args = parser.parse_args(argv)
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
            if not args.commit:
                parser.error("github needs --commit")
            token = require_env(
                "GH_RELEASE_TOKEN",
                "Add it as a Forgejo repository secret: a fine-grained GitHub token for"
                " jscott3201/rusty-bacnet with Contents read and write. Then re-run the release.",
            )
            host = GitHub(os.environ.get("GITHUB_REPO", "jscott3201/rusty-bacnet"), token)
            if args.wait_tag:
                wait_for_tag(host, args.tag, args.commit, args.wait_tag)
        publish(host, args.tag, notes, args.assets, args.dry_run)
    except (ReleaseError, OSError) as err:
        print(f"::error::{err}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
