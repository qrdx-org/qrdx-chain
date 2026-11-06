#!/usr/bin/env bash
# Fetch the execution-spec-tests fixtures release the EVM conformance run is pinned to, check its
# sha256, and extract its state tests (docs/EVM_CONFORMANCE.md).
#
#   scripts/conformance/fetch_eest.sh [DIR]        # default: .eest/ in the checkout
#   python scripts/conformance/eest_state_tests.py DIR/fixtures
#   QRDX_EEST_FIXTURES=DIR/fixtures pytest tests/test_evm_conformance.py
set -euo pipefail

VERSION="v5.4.0"
SHA256="92cf1b47ad12fb27163261fc3c1cea5df72439cab507983d06b56c94f8741909"
URL="https://github.com/ethereum/execution-spec-tests/releases/download/${VERSION}/fixtures_stable.tar.gz"

REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
DIR="${1:-$REPO/.eest}"
mkdir -p "$DIR"
ARCHIVE="$DIR/fixtures_stable-${VERSION}.tar.gz"

if [[ ! -f "$ARCHIVE" ]]; then
  curl -fsSL -o "$ARCHIVE.part" "$URL"
  mv "$ARCHIVE.part" "$ARCHIVE"
fi
echo "$SHA256  $ARCHIVE" | sha256sum -c - >/dev/null || {
  echo "sha256 mismatch for $ARCHIVE (expected $SHA256): delete it and fetch again" >&2
  exit 1
}
tar -xzf "$ARCHIVE" -C "$DIR" fixtures/state_tests
echo "$DIR/fixtures"
