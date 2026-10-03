# Changelog fragments

A change that users can see adds one file here instead of editing
`CHANGELOG.md`, so parallel PRs don't conflict over it. When a version is
released, `scripts/changelog.py assemble` writes the files into a new
`CHANGELOG.md` section and deletes them. This README is not a fragment.

## Writing a fragment

Name the file `<issue>-<short-slug>.md`, for example
`1131-access-door-oos-writes.md`, or `<short-slug>.md` when there is no
issue, using lowercase letters, digits and hyphens. When one issue needs two
entries, give each its own slug (`1092-units.md`, `1092-averaging.md`).

```markdown
---
section: Fixed
---
- **Breaking (wire):** Access Door accepts Door_Status, Lock_Status and
  Door_Alarm_State writes while out of service (#1131).
```

- `section` is the heading the entry goes under: `Added`, `Changed`,
  `Deprecated`, `Removed`, `Fixed`, `Security` or `Migration notes`.
- The body is one Markdown bullet starting with `- `, exactly as it will read
  in `CHANGELOG.md`. Indent continuation lines two spaces.
- Keep it short (#1188): one or two high-level sentences saying what changed
  for a user, naming the issue. No nested bullets, no second paragraph, and no
  datatypes, error codes or test lists: readers who want the detail follow the
  issue or the commit. `changelog.py check` rejects an entry over 300
  characters, or 500 under `Migration notes`, counting each line break as one
  space and a link by its text.
- Mark wire-format and breaking changes in bold, as above: `**Breaking
  (wire):**`, `**Breaking (Rust API):**`, `**Wire:**`, `**Python API:**` and so
  on.
- A breaking change that needs user action also adds a `Migration notes`
  fragment saying what to change, named `<issue>-<slug>-migration.md`:

  ```markdown
  ---
  section: Migration notes
  ---
  - **Group (Rust API, #1134):** `GroupObject::add_member` takes a
    `ReadAccessSpecification` and returns `Result`. `PropertyReference` and
    `ReadAccessSpecification` moved to `bacnet_types::constructed`, with
    their codecs in `bacnet_encoding::constructed`; update imports.
  ```

- Write relative links from the repository root (`docs/rust-api.md#bbmd`), as
  `CHANGELOG.md` will see them.
- No trailing whitespace, and the file ends with a single newline.

A release section lists its headings in the order above, and the entries
under each by issue number, then slug; fragments without an issue come last.
`assemble` ends each entry with a link to the GitHub commit that merged its
fragment into dev, so don't add one yourself.

## Pinning a commit

When history can't say which commit made a change (a bulk move created the
fragment, or a rebase rewrote it), add an optional `commit:` line after
`section:`:

```markdown
---
section: Fixed
commit: 0123456789abcdef0123456789abcdef01234567
---
```

- It takes 7 to 40 lowercase hex digits; write the full SHA.
- `assemble` and `preview` link that commit ahead of the history lookup, even
  in a shallow clone.
- `check` fails when the commit is on no mainline: the first-parent history
  of HEAD, of `MERGE_HEAD` during a merge, or of the local `origin/dev` or
  `dev` ref (dev's merge commits), so a branch that has merged dev still
  passes. A shallow clone, such as CI's lint checkout, skips that check
  without failing.
- `python3 scripts/changelog_pin_commits.py [--dry-run]` pins fragments that
  have no link where exactly one dev merge names their issue. It needs full
  history, and running it twice changes nothing.

Conformance ledger claims keep citing `CHANGELOG.md`, with the issue in the
note, since that is where the entry lands at release.

## Commands

```bash
python3 scripts/changelog.py check     # validate; CI's lint job runs this
python3 scripts/changelog.py preview   # print [Unreleased] as the fragments make it
python3 scripts/changelog.py assemble --version X.Y.Z [--date YYYY-MM-DD]   # at release
```

`check` also fails if `CHANGELOG.md`'s `[Unreleased]` section lists an entry
itself. The release steps are in [docs/ci.md](../docs/ci.md#release).
