#!/usr/bin/env python3
"""One-time backfill of `commit:` pins for fragments that have no commit link (#1217).

    changelog_pin_commits.py [--dry-run]

A bulk move (#1145's split into fragments) leaves changelog.py without a
commit to link. For each such fragment that names an issue, this finds the
merge commits on HEAD's first-parent history that name that issue and, when
there is exactly one, adds `commit: <full sha>` to the fragment's
front matter. Fragments with no such merge, or with several, stay unpinned
and are counted at the end.

A merge names the issue numbers in its pull request's title, like
"(#1219, #1220)", in either form of merge message:

    Merge pull request '<title>' (#<pr>) from <branch> into <base>
    Merge pull request #<pr> from <owner>/<branch>

The first holds the title in its subject. The second, GitHub's default, holds
it in the first line of the body. The pull request's own number doesn't count.
Any other merge names the issues in its subject. Run it on a branch cut from
dev with full history. It is idempotent: fragments that already have a pin or
a link are left alone.
"""

from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path

import changelog as cl

# A pull request merge's subject, with the title quoted in it.
TITLED_SUBJECT = re.compile(r"^Merge pull request '(.*)' \(#\d+\) from \S+ into \S+$")
# GitHub's default subject, whose body starts with the title.
GITHUB_SUBJECT = re.compile(r"^Merge pull request #\d+ from \S+$")
ISSUE_REF = re.compile(r"#(\d+)")


def merge_title(subject, body):
    """The pull request title a merge message holds (see the module docstring), or its subject."""
    m = TITLED_SUBJECT.match(subject)
    if m:
        return m.group(1)
    if GITHUB_SUBJECT.match(subject):
        return body.strip().split("\n", 1)[0]
    return subject


def merge_issues(root):
    """{issue number: [full SHA of each first-parent merge naming it]} on HEAD's history."""
    log = cl.git_out(root, "log", "--first-parent", "--merges", "--format=%H%x00%s%x00%b%x1e")
    merges = {}
    for record in log.split("\x1e"):
        if not record.strip():
            continue
        sha, subject, body = record.lstrip("\n").split("\0", 2)
        for number in {int(n) for n in ISSUE_REF.findall(merge_title(subject, body))}:
            merges.setdefault(number, []).append(sha)
    return merges


def pin(path, sha):
    """Add `commit: sha` after the section line of the fragment at path."""
    lines = path.read_text(encoding="utf-8").split("\n")
    lines.insert(2, f"commit: {sha}")  # parse_fragment guarantees the section line is line 2
    path.write_text("\n".join(lines), encoding="utf-8")


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--root", type=Path, default=cl.ROOT, help="repository root (default: this checkout)")
    parser.add_argument("--dry-run", action="store_true", help="report what would be pinned and write nothing")
    args = parser.parse_args(argv)

    try:
        fragments = cl.load_fragments(args.root / cl.FRAGMENT_DIR)
        if cl.full_history(args.root) is None:
            print("error: needs full git history at the top of the work tree (not a shallow clone)", file=sys.stderr)
            return 1
        links = cl.commit_links(args.root, fragments)
        merges = merge_issues(args.root)
    except (cl.ChangelogError, OSError) as err:
        print(f"error: {err}", file=sys.stderr)
        return 1

    pinned, ambiguous, unmatched = 0, [], []
    for fragment in fragments:
        if fragment.path in links:
            continue  # already pinned, or history links it
        if fragment.issue is None:
            unmatched.append(fragment)
            continue
        shas = merges.get(fragment.issue, [])
        if len(shas) == 1:
            pinned += 1
            if not args.dry_run:
                pin(fragment.path, shas[0])
        elif shas:
            ambiguous.append(fragment)
        else:
            unmatched.append(fragment)
    verb = "would pin" if args.dry_run else "pinned"
    print(f"{verb} {pinned} fragment(s); {len(ambiguous)} ambiguous and {len(unmatched)} unmatched stay unpinned.")
    for label, group in (("ambiguous", ambiguous), ("unmatched", unmatched)):
        for fragment in group:
            print(f"  {label}: {cl.FRAGMENT_DIR}/{fragment.path.name}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
