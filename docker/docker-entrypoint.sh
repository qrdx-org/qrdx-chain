#!/bin/bash
###############################################################################
# QRDX Node — container entrypoint
#
# Responsibilities
#   1. Apply container-appropriate defaults for the QRDX_* environment the node
#      reads (qrdx/constants.py takes os.environ over the .env file, so this
#      script only exports — it never writes /app/.env).
#   2. Ensure the writable paths the node needs exist: the SQLite directory and
#      the per-node PQ identity key directory.
#   3. Optionally expose the node on the public Internet via a Pinggy.io SSH
#      reverse tunnel, publishing the resulting URL to a shared peer registry.
#   4. Optionally resolve a bootstrap peer from that registry.
#   5. exec the node so it becomes PID 1 and receives signals directly.
#
# Environment (all optional unless noted)
#   NODE_NAME              Label used in logs and for the default self URL.
#   QRDX_NODE_HOST         Bind address inside the container   [0.0.0.0]
#   QRDX_NODE_PORT         Listen port inside the container    [3007]
#   QRDX_SELF_URL          Publicly reachable URL of this node [http://$NODE_NAME:$PORT]
#   QRDX_BOOTSTRAP_NODE    'self', 'discover', or an explicit URL
#   QRDX_BOOTSTRAP_NODES   Comma-separated peer list (defaults to the above)
#   QRDX_DATABASE_PATH     SQLite path                         [/app/data/qrdx.db]
#   QRDX_NODE_KEY_DIR      PQ node identity key directory      [/app/data/keys]
#   ENABLE_PINGGY_TUNNEL   'true' to open a public reverse tunnel
#
# NOTE: every QRDX_* variable is UPPERCASE. The node reads uppercase names only;
#       the lowercase `qrdx_*` spelling used by older revisions of this script was
#       silently ignored, leaving nodes bound to 127.0.0.1 and unreachable.
###############################################################################

set -euo pipefail

NODE_NAME="${NODE_NAME:-qrdx-node}"

echo "--- QRDX Node Container Entrypoint: ${NODE_NAME} ---"

# ---------------------------------------------------------------------------
# STAGE 1 — Defaults and writable paths
# ---------------------------------------------------------------------------
export QRDX_NODE_HOST="${QRDX_NODE_HOST:-0.0.0.0}"
export QRDX_NODE_PORT="${QRDX_NODE_PORT:-3007}"
export QRDX_DATABASE_PATH="${QRDX_DATABASE_PATH:-/app/data/qrdx.db}"
# Default the identity key directory into the data volume. Without this the node
# writes node_key.pq next to qrdx/node/main.py — inside the image layer, so the
# identity is lost on every redeploy (and fails outright on a read-only rootfs).
export QRDX_NODE_KEY_DIR="${QRDX_NODE_KEY_DIR:-/app/data/keys}"

export LOG_LEVEL="${LOG_LEVEL:-INFO}"
# Matches LOGGER_DEFAULTS in qrdx/constants.py; the logger already marks UTC.
export LOG_FORMAT="${LOG_FORMAT:-%(asctime)s - %(levelname)s - %(name)s - %(message)s}"
export LOG_DATE_FORMAT="${LOG_DATE_FORMAT:-%Y-%m-%dT%H:%M:%S}"
export LOG_CONSOLE_HIGHLIGHTING="${LOG_CONSOLE_HIGHLIGHTING:-True}"
export LOG_INCLUDE_REQUEST_CONTENT="${LOG_INCLUDE_REQUEST_CONTENT:-False}"
export LOG_INCLUDE_RESPONSE_CONTENT="${LOG_INCLUDE_RESPONSE_CONTENT:-False}"
export LOG_INCLUDE_BLOCK_SYNC_MESSAGES="${LOG_INCLUDE_BLOCK_SYNC_MESSAGES:-False}"

mkdir -p "$(dirname "${QRDX_DATABASE_PATH}")" "${QRDX_NODE_KEY_DIR}"
echo "Data directory:  $(dirname "${QRDX_DATABASE_PATH}")"
echo "Key directory:   ${QRDX_NODE_KEY_DIR}"

# The peer registry is only used by the Pinggy/discover flow; it lives on an
# optional shared volume, so a missing or read-only mount must not be fatal.
REGISTRY_DIR="${QRDX_PEER_REGISTRY_DIR:-/shared/node-registry}"
REGISTRY_FILE="${REGISTRY_DIR}/public_nodes.txt"
REGISTRY_AVAILABLE=false
if mkdir -p "${REGISTRY_DIR}" 2>/dev/null && touch "${REGISTRY_FILE}" 2>/dev/null; then
    REGISTRY_AVAILABLE=true
fi

# Default self URL to the container's in-network address.
export QRDX_SELF_URL="${QRDX_SELF_URL:-http://${NODE_NAME}:${QRDX_NODE_PORT}}"

# ---------------------------------------------------------------------------
# STAGE 2 — Optional public tunnel via Pinggy
# ---------------------------------------------------------------------------
if [ "${ENABLE_PINGGY_TUNNEL:-false}" = "true" ]; then
    echo "Pinggy tunnel enabled. Starting SSH reverse tunnel..."
    ssh -n -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null \
        -p 443 -R0:localhost:"${QRDX_NODE_PORT}" free.pinggy.io > /tmp/pinggy.log 2>&1 &

    PUBLIC_ADDRESS=""
    for _ in $(seq 1 30); do
        PUBLIC_ADDRESS="$(grep -o 'https://[a-zA-Z0-9-]*\.a\.free\.pinggy\.link' /tmp/pinggy.log | head -n 1 || true)"
        [ -n "${PUBLIC_ADDRESS}" ] && break
        sleep 1
    done

    if [ -n "${PUBLIC_ADDRESS}" ]; then
        echo "SUCCESS: public URL ${PUBLIC_ADDRESS}"
        export QRDX_SELF_URL="${PUBLIC_ADDRESS}"
        if [ "${REGISTRY_AVAILABLE}" = true ]; then
            echo "${PUBLIC_ADDRESS}" >> "${REGISTRY_FILE}"
            echo "Published public URL to the peer registry."
        fi
    else
        echo "WARNING: Pinggy did not return a public URL; falling back to the internal URL."
        export ENABLE_PINGGY_TUNNEL="false"
        tail -n 20 /tmp/pinggy.log || true
    fi
fi

# ---------------------------------------------------------------------------
# STAGE 3 — Bootstrap peer resolution
# ---------------------------------------------------------------------------
# An EMPTY QRDX_BOOTSTRAP_NODE is NOT the same as "no bootstrap": qrdx/constants.py
# treats an empty string as unset and falls back to the public seed node. A node
# that must not dial out (a local genesis bootstrap) therefore points at itself.
BOOTSTRAP="${QRDX_BOOTSTRAP_NODE:-}"

case "${BOOTSTRAP}" in
    "" | "self")
        BOOTSTRAP="${QRDX_SELF_URL}"
        ;;
    "discover")
        EXPECTED_URLS=1
        [ "${ENABLE_PINGGY_TUNNEL:-false}" = "true" ] && EXPECTED_URLS=2

        if [ "${REGISTRY_AVAILABLE}" != true ]; then
            echo "WARNING: discovery requested but no peer registry is mounted; using self."
            BOOTSTRAP="${QRDX_SELF_URL}"
        else
            echo "Discovery requested. Waiting for ${EXPECTED_URLS} public node(s)..."
            for _ in $(seq 1 60); do
                CURRENT="$(wc -l < "${REGISTRY_FILE}" 2>/dev/null || echo 0)"
                [ "${CURRENT}" -ge "${EXPECTED_URLS}" ] && break
                echo "  waiting... ${CURRENT}/${EXPECTED_URLS}"
                sleep 2
            done

            PEER="$(grep -v -F "${QRDX_SELF_URL}" "${REGISTRY_FILE}" 2>/dev/null | head -n 1 || true)"
            if [ -n "${PEER}" ]; then
                BOOTSTRAP="${PEER}"
                echo "Discovered bootstrap peer: ${BOOTSTRAP}"
            else
                echo "WARNING: no distinct peer discovered; using self."
                BOOTSTRAP="${QRDX_SELF_URL}"
            fi
        fi
        ;;
esac

export QRDX_BOOTSTRAP_NODE="${BOOTSTRAP}"
export QRDX_BOOTSTRAP_NODES="${QRDX_BOOTSTRAP_NODES:-${BOOTSTRAP}}"

# ---------------------------------------------------------------------------
# STAGE 4 — Launch
# ---------------------------------------------------------------------------
cat <<EOF
----------------------------------------
Node:       ${NODE_NAME}
Bind:       ${QRDX_NODE_HOST}:${QRDX_NODE_PORT}
Self URL:   ${QRDX_SELF_URL}
Bootstrap:  ${QRDX_BOOTSTRAP_NODE}
Database:   ${QRDX_DATABASE_PATH}
Validator:  ${QRDX_VALIDATOR_ENABLED:-false}
RPC (EVM):  ${QRDX_RPC_ENABLED:-false}
Streaming:  ${QRDX_ENABLE_STREAMING:-off}
----------------------------------------
EOF

# A custom command (e.g. `docker compose run <svc> python -m qrdx.cli.wallet`)
# wins over the default node launch.
if [ "$#" -gt 0 ]; then
    exec "$@"
fi

exec python /app/run_node.py
