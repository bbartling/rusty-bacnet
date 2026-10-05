#!/usr/bin/env bash
# Smoke-test a Linux wheel and CLI on the oldest system they support (#1472):
#
#   scripts/release/smoke_glibc217.sh <x86_64|aarch64> <version> <assets dir>
#
# On the runner it runs itself in the manylinux2014 image that the artifacts
# were built in (CentOS 7, glibc 2.17; pinned in .github/ci-pins.env), with the
# checkout at /io and <assets dir> inside it. In the image it installs the
# cp312 wheel into the image's CPython 3.12 and runs wheel_smoke.py, then
# cli_smoke.sh with the CLI, including the packet capture that its static
# libpcap does. check_artifacts.py has already checked that nothing in them
# needs a newer glibc; this shows that they run there.
set -euo pipefail

fail() { echo "error: smoke_glibc217.sh: $*" >&2; exit 1; }
[ $# -eq 3 ] || fail "usage: smoke_glibc217.sh <x86_64|aarch64> <version> <assets dir>"
arch=$1 version=$2 assets=$3
case $arch in
  x86_64) cli=bacnet-linux-amd64 pin_arch=X86_64 ;;
  aarch64) cli=bacnet-linux-arm64 pin_arch=AARCH64 ;;
  *) fail "unknown architecture $arch" ;;
esac
root=$(cd "$(dirname "$0")/../.." && pwd)

if [ "${RELEASE_IN_IMAGE:-}" != 1 ]; then
  digest=$(sed -n "s/^MANYLINUX2014_${pin_arch}_SHA256=//p" "$root/.github/ci-pins.env")
  [[ $digest =~ ^[0-9a-f]{64}$ ]] || fail "no MANYLINUX2014_${pin_arch}_SHA256 in .github/ci-pins.env"
  case $(cd "$assets" && pwd) in
    "$root"/*) ;;
    *) fail "$assets must be inside the checkout, which the image mounts" ;;
  esac
  exec docker run --rm -v "$root:/io" -w /io -e RELEASE_IN_IMAGE=1 \
    "quay.io/pypa/manylinux2014_$arch@sha256:$digest" \
    bash scripts/release/smoke_glibc217.sh "$arch" "$version" "$assets"
fi

ldd --version | sed -n 1p
python=/opt/python/cp312-cp312/bin/python
wheels=("$assets"/rusty_bacnet-*-cp312-cp312-manylinux*_"$arch".whl)
[ ${#wheels[@]} = 1 ] && [ -f "${wheels[0]}" ] || fail "expected one cp312 $arch wheel in $assets, found: ${wheels[*]}"
"$python" -m pip install -q --disable-pip-version-check --root-user-action=ignore --no-index --no-deps "${wheels[0]}"
"$python" -I scripts/release/wheel_smoke.py --version "$version"
chmod +x "$assets/$cli"
bash scripts/release/cli_smoke.sh --expect-version "$version" "$assets/$cli" "$python"
