#!/usr/bin/env bash
# Run the unit suite INSIDE a node image, against the code and dependencies the image ships
# (docs/RELEASES.md). The release workflow runs this on the candidate image before pushing it.
#
#   scripts/release/test-image.sh IMAGE [pytest args...]
#
# The image itself is not modified. A throwaway container gets the test tools from
# release/test-requirements.lock (hash-checked, constrained to the image's own versions) and a
# view of this checkout (mounted read-only) in which qrdx/ IS the image's /app/qrdx: every
# import of qrdx and every test that reads qrdx/ by path sees the shipped copy, and `eth` is the
# installed qrdx-evm wheel — both asserted before the suite runs. Everything else (tests/,
# docker/, release/, py-evm/ sources some tests read) comes from the checkout, which must be
# the commit the image was built from.
set -euo pipefail

REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
IMAGE="${1:?usage: test-image.sh IMAGE [pytest args...]}"; shift
PYTEST_ARGS=("$@")
[[ ${#PYTEST_ARGS[@]} -gt 0 ]] || PYTEST_ARGS=(tests -m "not integration" -q)

# Root only to install the test tools into the container's site-packages; the image's user is
# unchanged. /src is read-only, so nothing a test does can touch the checkout.
exec docker run --rm --user 0 \
  --entrypoint /bin/sh \
  -v "$REPO:/src:ro" \
  -e HOME=/tmp -e PYTHONDONTWRITEBYTECODE=1 \
  "$IMAGE" -c '
    set -eu
    pip install --quiet --root-user-action=ignore --no-compile --require-hashes --no-deps \
        -r /src/release/test-requirements.lock
    mkdir /tmp/repo
    for entry in /src/* /src/.[!.]*; do
      [ -e "$entry" ] || continue
      # Symlinked: everything but the shipped code, what is COPIED below, and a local
      # checkout'"'"'s runtime state (a test run writes logs/ and data/ of its own).
      case "${entry##*/}" in
        qrdx|tests|integration_tests|docker|scripts|*.py|logs|data|testnet*|ref|miner|dvm|.git) ;;
        *) ln -s "$entry" "/tmp/repo/${entry##*/}" ;;
      esac
    done
    ln -s /app/qrdx /tmp/repo/qrdx
    # Copied, not linked: test code writes next to itself (the integration harness puts its
    # testnet/ beside integration_tests/), and Python puts a script'"'"'s RESOLVED directory on
    # sys.path — a linked run_node.py would make every node it starts import /src/qrdx, the
    # checkout, instead of the shipped code.
    cp -R /src/tests /src/integration_tests /src/docker /src/scripts /tmp/repo/
    cp /src/*.py /tmp/repo/ 2>/dev/null || true
    find /tmp/repo -name __pycache__ -prune -exec rm -rf {} + 2>/dev/null || true
    cd /tmp/repo
    python - <<EOF
import os, sys
sys.path.insert(0, "/tmp/repo")  # what pytest (pythonpath = ".") will do
import qrdx, eth
where = os.path.realpath(qrdx.__file__)
assert where.startswith("/app/qrdx/"), f"testing {where}, not the shipped /app/qrdx"
assert not os.path.realpath(eth.__file__).startswith("/src/"), f"testing {eth.__file__}, not the installed qrdx-evm"
print(f"testing the shipped code: qrdx -> /app/qrdx, eth -> {os.path.dirname(eth.__file__)}")
EOF
    # ...and so does a script started from the workspace, as the harness starts run_node.py.
    printf "import os, qrdx; print(os.path.realpath(qrdx.__file__))\n" > /tmp/repo/_where.py
    where="$(python /tmp/repo/_where.py)"; rm -f /tmp/repo/_where.py
    case "$where" in
      /app/qrdx/*) echo "scripts started from the workspace import the shipped code too" ;;
      *) echo "a script started from the workspace imports $where, not /app/qrdx" >&2; exit 1 ;;
    esac
    exec python -m pytest -p no:cacheprovider "$@"
  ' sh "${PYTEST_ARGS[@]}"
