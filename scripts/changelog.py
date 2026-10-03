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
    ---
    - The entry: one Markdown bullet as it will read in CHANGELOG.md, with
      continuation lines indented two spaces.

check validates every fragment and fails if CHANGELOG.md's [Unreleased]
section lists entries itself; it keeps only a note pointing to changelog.d/.
With --no-fragments it also fails while any fragment is waiting (a release
tag must have assembled them all).

preview prints [Unreleased] as the fragments would assemble it.

assemble writes the fragments into CHANGELOG.md as a new `## [X.Y.Z] - date`
section below [Unreleased], grouped under the section headings in SECTIONS
order and sorted by issue number, then slug, within each. It deletes the
fragments it wrote and updates the compare links at the bottom of the file
if there are any. With --output it writes the result to that file instead and
leaves CHANGELOG.md and the fragments alone (release dry runs).
"""

from __future__ import annotations

import argparse
import datetime
import re
import sys
from dataclasses import dataclass
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
FRAGMENT_DIR = "changelog.d"
README = "README.md"

# The headings a fragment may name, in the order a release section lists them:
# Keep a Changelog's six, then the migration notes this changelog adds.
SECTIONS = ("Added", "Changed", "Deprecated", "Removed", "Fixed", "Security", "Migration notes")

NAME = re.compile(r"^(?:(\d+)-)?([a-z0-9]+(?:-[a-z0-9]+)*)\.md$")
VERSION = re.compile(r"^\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?$")
DATE = re.compile(r"^\d{4}-\d{2}-\d{2}$")
UNRELEASED = re.compile(r"^## \[Unreleased\]", re.IGNORECASE)
FENCE = re.compile(r"^\s*(```|~~~)")
LIST_ITEM = re.compile(r"^\s{0,3}(?:[-*+]|\d+[.)])(?:\s|$)")
HEADING = re.compile(r"^\s{0,3}#{1,6}(?:\s|$)")
UNRELEASED_LINK = re.compile(r"^\[Unreleased\]:\s*(\S+)/compare/(\S+?)\.\.\.(\S+)\s*$", re.IGNORECASE)


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
    if len(meta) != 1 or not meta[0].startswith("section:"):
        fail("the front matter holds exactly one key, 'section: <heading>'", 2)
    section = meta[0].removeprefix("section:").strip()
    if section not in SECTIONS:
        fail(f"section {section!r} is not one of: {', '.join(SECTIONS)}", 2)

    first = close + 1
    while first < len(lines) and lines[first] == "":
        first += 1
    body = lines[first:]
    if not body:
        fail("no entry after the front matter")
    if not body[0].startswith("- ") or not body[0][2:].strip():
        fail("the entry is one Markdown bullet starting with '- '", first + 1)
    for offset, line in enumerate(body[1:], first + 2):
        if line and not line.startswith("  "):
            fail("indent continuation lines two spaces; a fragment holds one top-level bullet", offset)

    issue = int(m.group(1)) if m.group(1) else None
    return Fragment(path, issue, m.group(2), section, "\n".join(body) + "\n")


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


def render(fragments):
    """The release section body: one heading per section, bullets in order."""
    out = []
    for section in SECTIONS:
        group = sorted((f for f in fragments if f.section == section), key=Fragment.sort_key)
        if not group:
            continue
        out.append(f"### {section}\n\n")
        out.append("\n".join(f.text for f in group))
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
        body = render(fragments) or f"No fragments in {FRAGMENT_DIR}/.\n"
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
        section = f"## [{version}] - {date}\n\n{render(fragments)}".rstrip("\n")
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
