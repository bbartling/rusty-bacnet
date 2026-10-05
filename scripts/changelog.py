#!/usr/bin/env python3
"""Check, preview and assemble the changelog fragments in changelog.d/.

    changelog.py check [--no-fragments]
    changelog.py preview
    changelog.py assemble --version 0.12.0 [--date 2026-10-02] [--output FILE]

A change adds one fragment file to changelog.d/ instead of editing
CHANGELOG.md, so parallel PRs don't conflict there. The file is named
<issue>-<slug>.md, or <slug>.md when there is no issue, and holds:

    ---
    section: Fixed
    commit: 0123abc   (optional, see below)
    ---
    - The entry: one short Markdown bullet as it will read in CHANGELOG.md,
      with continuation lines indented two spaces (#1188).

check validates every fragment and fails if CHANGELOG.md's [Unreleased]
section lists entries itself; it keeps only a note pointing to changelog.d/.
An entry is one paragraph with no nested bullets, at most ENTRY_CAP
characters (MIGRATION_CAP under Migration notes), counting each line break
and its indent as one space and leaving link targets out. With --no-fragments
it also fails while any fragment is waiting (a release tag must have
assembled them all).

preview prints [Unreleased] as the fragments would assemble it.

assemble writes the fragments into CHANGELOG.md as a new `## [X.Y.Z] - date`
section below [Unreleased], grouped under the section headings in SECTIONS
order and sorted by issue number, then slug, within each. Each entry ends
with a link to the GitHub commit that brought its fragment in along HEAD's
first-parent history: dev's merge commit, when run on a branch cut from dev.
A fragment that history doesn't add, or that a bulk move of more than
BULK_ADDS fragments added, gets no link, and neither does any unpinned entry in
a shallow clone. A fragment can pin its commit with `commit: <sha>` (7 to 40
lowercase hex digits) in the front matter; assemble and preview use that
ahead of the history lookup, and check fails when the repository has full
history and the pin is on no mainline: the first-parent history of HEAD, of
MERGE_HEAD during a merge, or of the local origin/dev or dev ref (a shallow
clone skips that check). scripts/changelog_pin_commits.py adds pins for fragments
a bulk move left without a link. assemble deletes the fragments it wrote and updates the compare
links at the bottom of the file if there are any. With --output it writes the
result to that file instead and leaves CHANGELOG.md and the fragments alone
(release dry runs). preview shows the same links.
"""

from __future__ import annotations

import argparse
import datetime
import re
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
FRAGMENT_DIR = "changelog.d"
README = "README.md"

# The headings a fragment may name, in the order a release section lists them:
# the migration notes this changelog adds and Security first, then the rest of
# Keep a Changelog's six. GitHub caps a release body, so notes that run long
# are cut from the end, and what an upgrade needs must come before that.
SECTIONS = ("Migration notes", "Security", "Added", "Changed", "Deprecated", "Removed", "Fixed")

# The longest entry, in characters, and the longest Migration notes entry,
# which also says what to change (#1188). Detail belongs in the issue.
ENTRY_CAP = 300
MIGRATION_CAP = 500

# Where an entry's commit link points: the repository on GitHub.
COMMIT_URL = "https://github.com/jscott3201/rusty-bacnet/commit/"
# A commit that adds more fragments than this moved existing entries (#1145
# split [Unreleased] into 209 of them) rather than making the changes, so its
# fragments get no link instead of all pointing at it.
BULK_ADDS = 20

# Refs whose first-parent lines count as mainlines for `commit:` pins, beside
# HEAD's. A branch that has merged dev holds dev's merge commits off its own
# first-parent line, and a merge in progress doesn't hold them in HEAD yet.
MAINLINE_REFS = ("MERGE_HEAD", "origin/dev", "dev")

NAME = re.compile(r"^(?:(\d+)-)?([a-z0-9]+(?:-[a-z0-9]+)*)\.md$")
VERSION = re.compile(r"^\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?$")
COMMIT = re.compile(r"^[0-9a-f]{7,40}$")
DATE = re.compile(r"^\d{4}-\d{2}-\d{2}$")
UNRELEASED = re.compile(r"^## \[Unreleased\]", re.IGNORECASE)
FENCE = re.compile(r"^\s*(```|~~~)")
LIST_ITEM = re.compile(r"^\s{0,3}(?:[-*+]|\d+[.)])(?:\s|$)")
HEADING = re.compile(r"^\s{0,3}#{1,6}(?:\s|$)")
UNRELEASED_LINK = re.compile(r"^\[Unreleased\]:\s*(\S+)/compare/(\S+?)\.\.\.(\S+)\s*$", re.IGNORECASE)
LINK_TARGET = re.compile(r"\[([^\]]*)\]\([^)\s]*\)")


class ChangelogError(Exception):
    """A fragment or CHANGELOG.md breaks the rules; the message says how."""


@dataclass(frozen=True)
class Fragment:
    """One validated fragment file."""

    path: Path
    issue: int | None
    slug: str
    section: str
    text: str  # the bullet, ending with a newline
    commit: str | None = None  # the pinned commit, as written

    def sort_key(self):
        """Issue number first, fragments without one last, then the slug."""
        return (self.issue is None, self.issue or 0, self.slug)


def parse_fragment(path):
    """Read and validate one fragment, raising ChangelogError on the first problem."""
    name = path.name

    def fail(msg, line=None):
        where = f"{FRAGMENT_DIR}/{name}" + (f":{line}" if line else "")
        raise ChangelogError(f"{where}: {msg}")

    m = NAME.match(name)
    if not m:
        fail("name it <issue>-<slug>.md, or <slug>.md without an issue, in lowercase letters, digits and hyphens")
    try:
        text = path.read_bytes().decode("utf-8")  # not read_text: keep any CR to report it
    except UnicodeDecodeError:
        fail("not UTF-8")
    if "\r" in text:
        fail("use LF line endings")
    if not text.endswith("\n"):
        fail("end the file with a newline")
    lines = text[:-1].split("\n")
    for i, line in enumerate(lines, 1):
        if line != line.rstrip():
            fail("trailing whitespace", i)
    if lines[-1] == "":
        fail("blank line at the end of the file", len(lines))

    if lines[0] != "---":
        fail("start with front matter: a '---' line, 'section: <heading>', then '---'", 1)
    try:
        close = lines.index("---", 1)
    except ValueError:
        fail("the front matter has no closing '---' line")
    meta = lines[1:close]
    if not meta or not meta[0].startswith("section:") or len(meta) > 2:
        fail("the front matter holds 'section: <heading>' and optionally 'commit: <sha>' after it", 2)
    section = meta[0].removeprefix("section:").strip()
    if section not in SECTIONS:
        fail(f"section {section!r} is not one of: {', '.join(SECTIONS)}", 2)
    commit = None
    if len(meta) == 2:
        if not meta[1].startswith("commit:"):
            fail("the front matter holds 'section: <heading>' and optionally 'commit: <sha>' after it", 3)
        commit = meta[1].removeprefix("commit:").strip()
        if not COMMIT.match(commit):
            fail(f"commit {commit!r} is not 7 to 40 lowercase hex digits", 3)

    first = close + 1
    while first < len(lines) and lines[first] == "":
        first += 1
    body = lines[first:]
    if not body:
        fail("no entry after the front matter")
    if not body[0].startswith("- ") or not body[0][2:].strip():
        fail("the entry is one Markdown bullet starting with '- '", first + 1)
    for offset, line in enumerate(body[1:], first + 2):
        if not line:
            fail("keep the entry to one paragraph; the issue and the commit carry the detail", offset)
        if not line.startswith("  "):
            fail("indent continuation lines two spaces; a fragment holds one top-level bullet", offset)
        if LIST_ITEM.match(line.lstrip()):
            fail("no nested bullets: one or two high-level sentences, with the detail left to the issue", offset)
    entry = "\n".join(body)
    cap = MIGRATION_CAP if section == "Migration notes" else ENTRY_CAP
    length = entry_length(entry)
    if length > cap:
        fail(f"the entry is {length} characters; keep it to {cap} (see {FRAGMENT_DIR}/{README})", first + 1)

    issue = int(m.group(1)) if m.group(1) else None
    return Fragment(path, issue, m.group(2), section, entry + "\n", commit)


def entry_length(entry):
    """An entry's length, counting each line break and its indent as one space and links by their text."""
    text = " ".join(line.strip() for line in entry.removeprefix("- ").split("\n"))
    return len(LINK_TARGET.sub(r"\1", text))


def load_fragments(directory):
    """Every fragment in directory, validated; ChangelogError lists all problems."""
    if not directory.is_dir():
        return []
    fragments, problems = [], []
    for path in sorted(directory.iterdir()):
        if path.name == README or path.name.startswith("."):
            continue
        if not path.is_file() or path.suffix != ".md":
            problems.append(f"{FRAGMENT_DIR}/{path.name}: only .md fragments and {README} belong here")
            continue
        try:
            fragments.append(parse_fragment(path))
        except ChangelogError as err:
            problems.append(str(err))
    if problems:
        raise ChangelogError("\n".join(problems))
    return fragments


def split_changelog(text):
    """(lines up to and including the [Unreleased] heading, its body, the rest)."""
    lines = text.splitlines()
    start = None
    in_fence = False
    for i, line in enumerate(lines):
        if FENCE.match(line):
            in_fence = not in_fence
            continue
        if in_fence or not line.startswith("## "):
            continue
        if start is not None:
            return lines[: start + 1], lines[start + 1 : i], lines[i:]
        if UNRELEASED.match(line):
            start = i
    if start is None:
        raise ChangelogError("CHANGELOG.md has no '## [Unreleased]' section")
    return lines[: start + 1], lines[start + 1 :], []


def unreleased_problems(body, offset):
    """Entries or headings in the [Unreleased] body, which only holds a note."""
    problems = []
    in_fence = False
    for i, line in enumerate(body, offset):
        if FENCE.match(line):
            in_fence = not in_fence
        if not in_fence and (LIST_ITEM.match(line) or HEADING.match(line)):
            problems.append(
                f"CHANGELOG.md:{i}: [Unreleased] keeps only a note; "
                f"add the entry as a {FRAGMENT_DIR}/ fragment (see {FRAGMENT_DIR}/{README})"
            )
    return problems


def git_out(root, *args):
    """Stdout of `git -C root args`, stripped; raises OSError or CalledProcessError."""
    cmd = ["git", "-C", str(root), *args]
    return subprocess.run(cmd, capture_output=True, text=True, check=True).stdout.strip()


def full_history(root):
    """HEAD's first-parent commits, newest first, or None without full history.

    None when root isn't the top of a git work tree, in a shallow clone (whose
    oldest commit seems to add every file), or without git.
    """
    root = Path(root)
    try:
        if Path(git_out(root, "rev-parse", "--show-toplevel")).resolve() != root.resolve():
            return None
        if git_out(root, "rev-parse", "--is-shallow-repository") != "false":
            return None
        return git_out(root, "rev-list", "--first-parent", "HEAD").split()
    except (OSError, subprocess.CalledProcessError):
        return None


def mainline_commits(root):
    """Commits on any mainline a pin may name, HEAD's first-parent line first, or None without full history.

    The other mainlines are the first-parent lines of the MAINLINE_REFS that
    exist, so a pin to a dev merge commit still resolves on a branch that has
    merged dev, or is merging it, and a side-branch commit still doesn't.
    """
    history = full_history(root)
    if history is None:
        return None
    seen = set(history)
    for ref in MAINLINE_REFS:
        try:
            tip = git_out(root, "rev-parse", "-q", "--verify", f"{ref}^{{commit}}")
            line = git_out(root, "rev-list", "--first-parent", tip).split()
        except (OSError, subprocess.CalledProcessError):
            continue
        history += [sha for sha in line if sha not in seen]
        seen.update(line)
    return history


def pinned_sha(pin, history):
    """The full SHA a pin names in history, or the pin as written when history can't say."""
    if history is None:
        return pin
    hits = [sha for sha in history if sha.startswith(pin)]
    return hits[0] if len(hits) == 1 else pin


def commit_links(root, fragments):
    """{fragment path: SHA} of the commit that added each fragment along HEAD's first-parent history.

    On dev, or a branch cut from it, that is the merge commit that brought the
    fragment in. A commit that added more than BULK_ADDS fragments links none.
    A fragment's `commit:` pin wins over all of that, and works without history.
    Otherwise empty when root has no full git history (see full_history).
    """
    history = full_history(root)
    mainlines = mainline_commits(root) if any(f.commit for f in fragments) else history
    links = {f.path: pinned_sha(f.commit, mainlines) for f in fragments if f.commit}
    if history is None:
        return links
    try:
        log = git_out(
            root, "log", "--first-parent", "--diff-merges=first-parent", "--diff-filter=A", "--no-renames",
            "--name-only", "--format=%x00%H", "--", FRAGMENT_DIR,
        )
    except (OSError, subprocess.CalledProcessError):
        return links
    added, adds, sha = {}, {}, None
    for line in log.splitlines():
        if line.startswith("\0"):
            sha = line[1:]
        elif line and sha:
            added.setdefault(line, sha)  # newest first, so a fragment added again keeps its latest commit
            adds[sha] = adds.get(sha, 0) + 1
    for f in fragments:
        name = f"{FRAGMENT_DIR}/{f.path.name}"
        if f.path not in links and name in added and adds[added[name]] <= BULK_ADDS:
            links[f.path] = added[name]
    return links


def pin_problems(root, fragments):
    """One message per `commit:` pin that is on no mainline (see mainline_commits); none without full history."""
    pinned = [f for f in fragments if f.commit]
    history = mainline_commits(root) if pinned else None
    if history is None:
        return []
    problems = []
    for f in pinned:
        hits = [sha for sha in history if sha.startswith(f.commit)]
        where = f"{FRAGMENT_DIR}/{f.path.name}"
        if not hits:
            problems.append(f"{where}: commit {f.commit} is on no mainline's first-parent history")
        elif len(hits) > 1:
            problems.append(f"{where}: commit {f.commit} is ambiguous; write more of the SHA")
    return problems


def linked(fragment, sha):
    """The fragment's entry, ending with a link to its commit when there is one."""
    if sha is None:
        return fragment.text
    return f"{fragment.text.removesuffix(chr(10))} ([{sha[:7]}]({COMMIT_URL}{sha}))\n"


def render(fragments, links=None):
    """The release section body: one heading per section, bullets in order, each with its commit link."""
    links = links or {}
    out = []
    for section in SECTIONS:
        group = sorted((f for f in fragments if f.section == section), key=Fragment.sort_key)
        if not group:
            continue
        out.append(f"### {section}\n\n")
        out.append("\n".join(linked(f, links.get(f.path)) for f in group))
        out.append("\n")
    return "".join(out).removesuffix("\n")


def update_links(lines, version):
    """Point a `[Unreleased]: .../compare/A...B` link past version and add version's link."""
    if any(line.lower().startswith(f"[{version.lower()}]:") for line in lines):
        return lines
    for i, line in enumerate(lines):
        m = UNRELEASED_LINK.match(line)
        if m:
            base, prev, head = m.groups()
            tag = f"v{version}" if prev.startswith("v") else version
            return [
                *lines[:i],
                f"[Unreleased]: {base}/compare/{tag}...{head}",
                f"[{version}]: {base}/compare/{prev}...{tag}",
                *lines[i + 1 :],
            ]
    return lines


class Changelog:
    """CHANGELOG.md and changelog.d/ under one repository root."""

    def __init__(self, root):
        self.root = Path(root)
        self.path = Path(root) / "CHANGELOG.md"
        self.directory = Path(root) / FRAGMENT_DIR

    def read(self):
        """CHANGELOG.md split around [Unreleased], failing if that section lists entries."""
        head, body, rest = split_changelog(self.path.read_text(encoding="utf-8"))
        problems = unreleased_problems(body, len(head) + 1)
        if problems:
            raise ChangelogError("\n".join(problems))
        return head, body, rest

    def check(self, no_fragments=False):
        """Validate everything; return the fragment count."""
        problems = []
        fragments = []
        try:
            fragments = load_fragments(self.directory)
        except ChangelogError as err:
            problems.append(str(err))
        try:
            self.read()
        except ChangelogError as err:
            problems.append(str(err))
        problems.extend(pin_problems(self.root, fragments))
        if no_fragments and fragments:
            problems.append(
                f"{len(fragments)} fragment(s) in {FRAGMENT_DIR}/ are not in a release section; "
                "run changelog.py assemble before tagging"
            )
        if problems:
            raise ChangelogError("\n".join(problems))
        return len(fragments)

    def preview(self):
        """[Unreleased] as the fragments would assemble it."""
        fragments = load_fragments(self.directory)
        self.read()
        body = render(fragments, commit_links(self.root, fragments)) or f"No fragments in {FRAGMENT_DIR}/.\n"
        return f"## [Unreleased]\n\n{body}"

    def assemble(self, version, date, output=None, allow_empty=False):
        """Write the release section; return the fragments it took."""
        fragments = load_fragments(self.directory)
        head, body, rest = self.read()
        if not fragments and not allow_empty:
            raise ChangelogError(f"no fragments in {FRAGMENT_DIR}/ to assemble")
        heading = re.compile(rf"^## \[{re.escape(version)}\]", re.IGNORECASE)
        if any(heading.match(line) for line in rest):
            raise ChangelogError(f"CHANGELOG.md already has a '## [{version}]' section")

        while body and not body[-1].strip():
            body = body[:-1]
        section = f"## [{version}] - {date}\n\n{render(fragments, commit_links(self.root, fragments))}".rstrip("\n")
        lines = [*head, *body, "", *section.splitlines(), *([""] + rest if rest else [])]
        text = "\n".join(update_links(lines, version)) + "\n"

        if output is not None:
            Path(output).write_text(text, encoding="utf-8")
            return fragments
        self.path.write_text(text, encoding="utf-8")
        for fragment in fragments:
            fragment.path.unlink()
        return fragments


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--root", type=Path, default=ROOT, help="repository root (default: this checkout)")
    sub = parser.add_subparsers(dest="command", required=True)
    check = sub.add_parser("check", help="validate the fragments and the [Unreleased] note")
    check.add_argument("--no-fragments", action="store_true", help="also fail while any fragment is waiting")
    sub.add_parser("preview", help="print [Unreleased] as the fragments would assemble it")
    assemble = sub.add_parser("assemble", help="write the fragments into a release section")
    assemble.add_argument("--version", required=True, help="release version, for example 0.12.0")
    assemble.add_argument("--date", help="release date, YYYY-MM-DD (default: today)")
    assemble.add_argument("--output", type=Path, help="write the result here; keep CHANGELOG.md and the fragments")
    assemble.add_argument("--allow-empty", action="store_true", help="assemble even with no fragments")
    args = parser.parse_args(argv)

    changelog = Changelog(args.root)
    try:
        if args.command == "check":
            count = changelog.check(args.no_fragments)
            print(f"OK: {count} fragment(s) in {FRAGMENT_DIR}/, and [Unreleased] holds no entries.")
        elif args.command == "preview":
            sys.stdout.write(changelog.preview())
        else:
            version = args.version.removeprefix("v")
            if not VERSION.match(version):
                parser.error(f"--version {args.version!r} is not X.Y.Z")
            date = args.date or datetime.date.today().isoformat()
            try:
                datetime.date.fromisoformat(date)
                valid = DATE.match(date) is not None
            except ValueError:
                valid = False
            if not valid:
                parser.error(f"--date {date!r} is not YYYY-MM-DD")
            taken = changelog.assemble(version, date, args.output, args.allow_empty)
            target = args.output or changelog.path
            print(f"Assembled {len(taken)} fragment(s) into '## [{version}] - {date}' in {target}.")
    except (ChangelogError, OSError) as err:
        print(f"error: {err}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
