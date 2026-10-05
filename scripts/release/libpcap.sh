#!/usr/bin/env bash
# Fetch libpcap's source at the version pinned in .github/ci-pins.env (#1472):
#
#   scripts/release/libpcap.sh <dir>
#
# Downloads libpcap-<version>.tar.xz from tcpdump.org, checks it against the
# pinned SHA-256 before unpacking anything, and leaves:
#   <dir>/src      the source tree, which build_linux.sh builds;
#   <dir>/LICENSE  its licence, and
#   <dir>/VERSION  its version, both for third_party_notices.py --libpcap.
# Needs curl, sha256sum and an xz-capable tar: the Ubuntu runners and the
# manylinux2014 image have them.
set -euo pipefail

fail() { echo "error: libpcap.sh: $*" >&2; exit 1; }
[ $# -eq 1 ] || fail "usage: libpcap.sh <dir>"
dir=$1
root=$(cd "$(dirname "$0")/../.." && pwd)
pins=$root/.github/ci-pins.env

pin() {
  local value
  value=$(sed -n "s/^$1=//p" "$pins")
  [[ $value =~ ^[0-9A-Za-z.]+$ ]] || fail "no single $1 in $pins"
  printf '%s\n' "$value"
}

version=$(pin LIBPCAP_VERSION)
sha256=$(pin LIBPCAP_SHA256)
mkdir -p "$dir/src"
archive=$dir/libpcap-$version.tar.xz
curl -sSfL --retry 3 -o "$archive" "https://www.tcpdump.org/release/libpcap-$version.tar.xz"
echo "$sha256  $archive" | sha256sum -c --quiet - || fail "libpcap-$version.tar.xz does not match its pinned SHA-256"
tar xJf "$archive" -C "$dir/src" --strip-components=1
rm "$archive"
cp "$dir/src/LICENSE" "$dir/LICENSE"
echo "$version" >"$dir/VERSION"
echo "libpcap $version in $dir/src"
