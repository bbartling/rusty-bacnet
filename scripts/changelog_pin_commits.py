#!/usr/bin/env python3
"""One-time backfill of `commit:` pins for fragments that have no commit link (#1217).

    changelog_pin_commits.py [--dry-run]

A bulk move (#1145's split into fragments) leaves changelog.py without a
commit to link. For each such fragment that names an issue, this finds the
merge commits on HEAD's first-parent history whose subject names that issue
and, when there is exactly one, adds `commit: <full sha>` to the fragment's
front matter. Fragments with no such merge, or with several, stay unpinned
and are counted at the end.

Names in a merge subject are the issue numbers inside the quoted pull request
title, like "(#1219, #1220)"; the pull request's own number after the title
doesn't count. Run it on a branch cut from dev with full history. It is
idempotent: fragments that already have a pin or a link are left alone.
"""

from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path

import changelog as cl

# Forgejo's merge subject: Merge pull request '<title>' (#<pr>) from <branch> into <base>
PR_SUBJECT = re.compile(r"^Merge pull request '(.*)' \(#\d+\) from \S+ into \S+$")
ISSUE_REF = re.compile(r"#(\d+)")


def merge_issues(root):
    """{issue number: [full SHA of each first-parent merge naming it]} on HEAD's history."""
    log = cl.git_out(root, "log", "--first-parent", "--merges", "--format=%H%x00%s")
    merges = {}
    for line in log.splitlines():
        sha, _, subject = line.partition("\0")
        m = PR_SUBJECT.match(subject)
        title = m.group(1) if m else subject
        for number in {int(n) for n in ISSUE_REF.findall(title)}:
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
