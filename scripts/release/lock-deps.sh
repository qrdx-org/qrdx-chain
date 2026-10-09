#!/usr/bin/env bash
# Compile the release locks (docs/RELEASES.md) — exact versions and sha256 of every artifact:
#
#   release/requirements.lock        what the node image installs (requirements-v3.txt + py-evm)
#   release/build-requirements.lock  build backends for the dependencies that ship only as source
#   release/test-requirements.lock   test tools, constrained by requirements.lock
#
#   scripts/release/lock-deps.sh                   re-lock, keeping every current pin that still
#                                                  satisfies the inputs (the usual case: after
#                                                  editing requirements-v3.txt)
#   scripts/release/lock-deps.sh --upgrade         re-resolve everything to the newest allowed
#   scripts/release/lock-deps.sh --upgrade-package NAME [...]   move only these
#   scripts/release/lock-deps.sh --check           exit 1 if any lock is stale (CI)
#
# Locks are resolved for Python 3.11 (the image's) on every platform, so the same lock serves
# amd64 and arm64. A changed lock is a reviewed change: diff it, and run the image tests
# (scripts/release/test-image.sh) before merging it.
set -euo pipefail

REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
PYTHON_VERSION="3.11"
CHECK=0; EXTRA=()
while [[ $# -gt 0 ]]; do
  case "$1" in
    --check) CHECK=1; shift ;;
    --upgrade) EXTRA+=(--upgrade); shift ;;
    --upgrade-package) EXTRA+=(--upgrade-package "$2"); shift 2 ;;
    -h|--help) sed -n '2,17p' "$0"; exit 0 ;;
    *) echo "unknown option: $1" >&2; exit 2 ;;
  esac
done
if [[ "$CHECK" == 1 && ${#EXTRA[@]} -gt 0 ]]; then
  echo "--check takes no upgrade options" >&2; exit 2
fi
command -v uv >/dev/null || { echo "uv is required (https://docs.astral.sh/uv/)" >&2; exit 2; }

WORK="$(mktemp -d)"; trap 'rm -rf "$WORK"' EXIT
# Paths inside the .in files are relative to release/, and uv records them as written — so
# compile from there, and the locks never mention this machine's paths.
cd "$REPO/release"

# compile IN LOCK [extra uv args...]
compile() {
  local in="$1" lock="$2"; shift 2
  local out="$lock"
  if [[ "$CHECK" == 1 ]]; then
    # Compile into a copy: uv keeps the pins it finds in the output file, so an up-to-date lock
    # compiles to itself and only a stale one changes.
    out="$WORK/$lock"; cp "$lock" "$out"
  fi
  uv pip compile "$in" --universal --python-version "$PYTHON_VERSION" --generate-hashes \
      --no-header --quiet "$@" ${EXTRA[@]+"${EXTRA[@]}"} -o "$out"
  if [[ "$CHECK" == 1 ]]; then
    if ! diff -u "$lock" "$out" >"$WORK/$lock.diff"; then
      echo "release/$lock is stale — run scripts/release/lock-deps.sh and commit the result:" >&2
      cat "$WORK/$lock.diff" >&2
      return 1
    fi
    echo "release/$lock is up to date"
  else
    echo "wrote release/$lock"
  fi
}

status=0
# py-evm is installed from the submodule (its own wheel, built in the image), not from an index.
compile requirements.in requirements.lock --no-emit-package qrdx-evm || status=1
compile build-requirements.in build-requirements.lock || status=1
compile test-requirements.in test-requirements.lock -c requirements.lock || status=1
exit "$status"
