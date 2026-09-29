#!/usr/bin/env bash
# Synthetic scanner regressions. No real credentials are used or printed.
set -euo pipefail

scanner="$(cd "$(dirname "$0")" && pwd)/check-no-secrets.sh"
fixture=$(mktemp -d)
trap 'rm -rf "$fixture"' EXIT
cd "$fixture"
git init -q

fail() {
  echo "FAIL: scanner regression: $1" >&2
  exit 1
}

expect_clean() {
  bash "$scanner" >result.log 2>&1 || fail "$1"
  grep -q 'OK: baseline no-secret scan clean.' result.log || fail 'missing clean status'
}

expect_match() {
  local status=0
  bash "$scanner" >result.log 2>&1 || status=$?
  [ "$status" -eq 1 ] || fail "$1 did not exit 1"
  grep -q '\[REDACTED\]' result.log || fail "$1 missing redacted location"
  if grep -F -q -e "$value" result.log; then
    fail "$1 leaked synthetic matching text"
  fi
}

expect_location() {
  local path_id
  path_id=$(printf '%s' "$1" | git hash-object --stdin)
  grep -F -q -e "path-id=$path_id:$2: [REDACTED]" result.log || fail 'wrong path ID/line'
}

printf 'ordinary tracked content\n' >tracked.txt
git add tracked.txt
expect_clean 'ordinary tracked content'

# Build examples in pieces to avoid embedding secret-shaped literals in source.
aws="AKIA$(printf '%016d' 0)"
slack="xoxb-$(printf '%010d' 0)"
github="ghp_$(printf '%036d' 0)"
api="sk-$(printf '%020d' 0)"
private_key="-----BEGIN RSA PRIVATE"
private_key="$private_key KEY-----"

for value in "$aws" "$slack" "$github" "$api" "$private_key"; do
  printf 'safe first line\n%s\n' "$value" >tracked.txt
  expect_match 'tracked pattern'
  expect_location tracked.txt 2
done

printf 'ordinary tracked content\n' >tracked.txt
printf '%s\n' "$aws" >untracked.txt
mkdir _spec
printf '%s\n' "$aws" >_spec/excluded.txt
git add _spec/excluded.txt
expect_clean 'untracked and _spec exclusions'

odd_path=$'colon:space and\nnewline.txt'
value="$aws"
printf '%s\n' "$value" >"$odd_path"
git add "$odd_path"
expect_match 'unusual filename'
expect_location "$odd_path" 1
rm "$odd_path"
git add -u

printf '\0%s\n' "$value" >binary.dat
git add binary.dat
expect_match 'binary tracked content'
expect_location binary.dat 1
rm binary.dat
git add -u

# Every pattern family can occur in a filename, even when a different family
# triggered the content match. Neither the path nor its contents may be echoed.
for filename_value in "$aws" "$slack" "$github" "$api" "$private_key"; do
  secret_path="fixture-$filename_value.txt"
  value="$aws"
  printf 'safe first line\n%s\n' "$value" >"$secret_path"
  git add -- "$secret_path"
  expect_match 'secret-shaped filename'
  expect_location "$secret_path" 2
  if grep -F -q -e "$filename_value" result.log; then
    fail 'secret-shaped filename leaked'
  fi
  rm -- "$secret_path"
  git add -u
done

for ((i = 0; i < 25; i++)); do printf '%s\n' "$value"; done >tracked.txt
expect_match 'repeated pattern'
[ "$(grep -c '\[REDACTED\]' result.log)" -eq 20 ] || fail 'diagnostic limit'
grep -q 'additional matches omitted' result.log || fail 'missing truncation notice'

status=0
GIT_DIR="$fixture/missing-git-dir" bash "$scanner" >result.log 2>&1 || status=$?
[ "$status" -eq 2 ] || fail 'git error treated as clean scan'
grep -q 'ERROR: unable to scan tracked files.' result.log || fail 'missing scan error'

echo 'OK: no-secret scanner regression checks passed.'
