#!/usr/bin/env bash
# Baseline no-secret scan. Greps tracked files for common secret-shaped
# patterns. `_spec/` is excluded — it's an untracked working area, but
# the exclusion is defense-in-depth in case anyone accidentally tracks
# coordination notes that quote credentials.

set -euo pipefail

violations=0

scan() {
  local pattern="$1"
  local label="$2"
  local path path_id line matched status count=0 limit=20
  if git grep -qE -e "$pattern" -- ':(exclude)_spec' 2>/dev/null; then
    echo "FAIL: matched $label pattern in tracked files:"
    # NUL-delimited path/line fields handle colons and newlines in filenames.
    # Consume matching text without printing it, including for binary files.
    # Limit diagnostics per pattern so repeated matches cannot flood CI logs.
    while IFS= read -r -d '' path && IFS= read -r -d '' line && IFS= read -r matched; do
      if [ "$count" -ge "$limit" ]; then
        echo "  (additional matches omitted)"
        break
      fi
      # Filenames can contain credentials too. Hash the path bytes without
      # writing an object; retain a stable location ID without echoing a path.
      path_id=$(printf '%s' "$path" | git hash-object --stdin)
      printf '  path-id=%s:%s: [REDACTED]\n' "$path_id" "$line"
      count=$((count + 1))
    done < <(git grep --text -n -z -E -e "$pattern" -- ':(exclude)_spec' || true)
    violations=$((violations + 1))
  else
    status=$?
    if [ "$status" -ne 1 ]; then
      echo 'ERROR: unable to scan tracked files.' >&2
      exit 2
    fi
  fi
}

scan 'AKIA[0-9A-Z]{16}' 'AWS access key id'
scan '-----BEGIN (RSA|EC|OPENSSH|PGP) PRIVATE KEY-----' 'private key block'
scan 'xox[abpr]-[A-Za-z0-9-]{10,}' 'Slack token'
scan 'gh[pousr]_[A-Za-z0-9]{36,}' 'GitHub token'
scan 'sk-[A-Za-z0-9_-]{20,}' 'API token (sk- prefix)'

if [ "$violations" -gt 0 ]; then
  echo
  echo "Remove secrets from the working tree, rotate compromised credentials, and rewrite history."
  exit 1
fi

echo "OK: baseline no-secret scan clean."
