#!/usr/bin/env bash
# Deletes the GitHub Actions cache entries that no run will restore again
# (#1471). The repository gets 10 GB of cache; past that, GitHub evicts the
# least recently used entries, which can include dev's current ones, and every
# PR then builds from cold. Only runs on dev save Rust caches (ci.yml and
# native-tests.yml), and every other ref restores dev's, so this keeps:
#
#   - on refs/heads/dev, the two newest rust-cache entries (key v0-rust-*) of
#     each family, and every entry of another tool (setup-node's npm cache);
#   - on any other ref, nothing: a PR's entries can only be read by that PR's
#     runs, and Rust caches are never saved there.
#
# A family is the key without its last two parts, the toolchain and
# environment hash and the Cargo.lock and manifest hash: one job on one OS,
# such as v0-rust-test-Linux-x64. A lock, toolchain or feature-list change
# saves a new entry, and the old one would otherwise stay until it had gone
# unused for seven days.
#
# Runs on dev don't finish in merge order, so the newest entry of a family can
# come from an older merge. Two guards keep that from deleting the entry the
# current dev head uses: only the run for dev's head prunes (another run logs
# that and exits 0), and each family keeps its two newest entries.
#
# Both workflows run it after a successful run on dev, with a token that has
# `actions: write`. It logs every deletion, and --dry-run lists them without
# deleting anything (a token that can read the caches is enough; outside a
# workflow, with no GITHUB_SHA, it skips the dev-head check):
#
#   GH_TOKEN=... bash scripts/ci/prune-caches.sh [--dry-run] [owner/repo]
set -euo pipefail

dry_run=false
if [ "${1:-}" = --dry-run ]; then dry_run=true; shift; fi
repo=${1:-${GITHUB_REPOSITORY:?pass owner/repo or set GITHUB_REPOSITORY}}
keep_ref=refs/heads/dev
keep=2

head=$(gh api "repos/$repo/commits/${keep_ref#refs/heads/}" --jq .sha)
if [ -n "${GITHUB_SHA:-}" ]; then
  if [ "$GITHUB_SHA" != "$head" ]; then
    echo "This run is for $GITHUB_SHA, but dev is now at $head; the run for dev's head prunes."
    exit 0
  fi
elif ! $dry_run; then
  echo "::error::GITHUB_SHA is not set; outside a workflow, use --dry-run"
  exit 1
fi

# One line per entry, newest first: id, ref, key, created_at, size in bytes.
# ISO 8601 timestamps sort as text.
entries=$(gh api --paginate "repos/$repo/actions/caches?per_page=100" \
  --jq '.actions_caches[] | [.id, .ref, .key, .created_at, .size_in_bytes] | @tsv' \
  | sort -t "$(printf '\t')" -k4,4r)

# The entries to delete, each with the reason.
doomed=$(awk -F '\t' -v OFS='\t' -v keep_ref="$keep_ref" -v keep="$keep" '
  $2 != keep_ref { print $0, "ref " $2; next }
  $3 ~ /^v0-rust-/ {
    family = $3
    sub(/-[^-]*-[^-]*$/, "", family)
    if (++seen[family] > keep) print $0, "older than the " keep " newest of " family
  }' <<<"$entries")

mib() { echo "$(( ($1 + 524288) / 1048576 )) MiB"; }
total=0 count=0
while IFS=$'\t' read -r _ _ _ _ size; do
  [ -n "$size" ] || continue
  total=$((total + size)) count=$((count + 1))
done <<<"$entries"
echo "$count cache entries, $(mib "$total") in all"

freed=0 removed=0 failed=0
while IFS=$'\t' read -r id ref key created size reason; do
  [ -n "$id" ] || continue
  line="$key on $ref, $(mib "$size"), created $created: $reason"
  if $dry_run; then
    echo "would delete $line"
  elif out=$(gh api -X DELETE "repos/$repo/actions/caches/$id" 2>&1); then
    echo "deleted $line"
  elif grep -q 'HTTP 404' <<<"$out"; then
    # The other workflow's prune got there first.
    echo "already gone: $line"
  else
    echo "::error::could not delete $line: $out"
    failed=$((failed + 1))
    continue
  fi
  freed=$((freed + size)) removed=$((removed + 1))
done <<<"$doomed"

summary="$removed entries, $(mib "$freed"), leaving $(mib $((total - freed)))"
if $dry_run; then echo "would remove $summary"; else echo "removed $summary"; fi
[ "$failed" -eq 0 ]
