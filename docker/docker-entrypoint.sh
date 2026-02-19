#!/bin/bash

###############################################################################
# qrdx Node Container Entrypoint
#
# Overview
#   This script launches a qrdx node inside a container. It prepares runtime
#   configuration, optionally acquires a public URL via Pinggy, coordinates
#   bootstrap peer discovery through a registry file, ensures the SQLite
#   database directory exists, then starts the qrdx node process.
#
# Lifecycle and responsibilities
#   1. Initialization:
#        - The shared peer registry directory is created
#        - A deterministic internal self URL is derived.
#        - Bootstrap intent is normalized when unset.
#
#   2. Public URL acquisition and publication:
#        - If tunneling is enabled, a reverse tunnel is established via ssh
#          using Pinggy free tunneling service (free.pinggy.io).
#
#   3. Peer discovery:
#        - Public bootstrap nodes wait for the appearance of another public peer.
#        - Private nodes in discovery mode wait for any public node.
#
#   4. Env generation, database directory creation, and application launch:
#        - An application .env file is generated with the required variables.
#        - The SQLite database directory is created if it does not exist.
#        - The qrdx node is started via python run_node.py.
#
# Inputs via environment:
#   NODE_NAME                   Name of this node
#   qrdx_NODE_HOST            Hostname or IP the node binds to or advertises
#   qrdx_NODE_PORT            Port that the node listens on inside the container
#   ENABLE_PINGGY_TUNNEL        When "true", Pinggy tunneling is enabled
#   qrdx_BOOTSTRAP_NODE       "self", "discover", or any explicit URL
#   QRDX_DATABASE_PATH          Path to the SQLite database file
#
###############################################################################

set -e

echo "--- qrdx Node Container Entrypoint for ${NODE_NAME} ---"

# --- CONFIGURATION ---
REGISTRY_DIR="/shared/node-registry"
REGISTRY_FILE="${REGISTRY_DIR}/public_nodes.txt"
mkdir -p "$REGISTRY_DIR"

# Default database path
if [ -z "${QRDX_DATABASE_PATH}" ]; then
  export QRDX_DATABASE_PATH="/app/data/qrdx.db"
fi

# Default to internal URL if unset
if [ -z "${qrdx_SELF_URL}" ]; then
  export qrdx_SELF_URL="http://${NODE_NAME}:${qrdx_NODE_PORT}"
fi

# Normalize bootstrap intent default if unset
if [ -z "${qrdx_BOOTSTRAP_NODE}" ]; then
  export qrdx_BOOTSTRAP_NODE="https://node.qrdx.network"
fi

if [ -z "${LOG_LEVEL}" ]; then export LOG_LEVEL="INFO"; fi
if [ -z "${LOG_FORMAT}" ]; then export LOG_FORMAT="%(asctime)s UTC - %(levelname)s - %(name)s - %(message)s"; fi
if [ -z "${LOG_DATE_FORMAT}" ]; then export LOG_DATE_FORMAT="%Y-%m-%dT%H:%M:%S"; fi
if [ -z "${LOG_INCLUDE_REQUEST_CONTENT}" ]; then export LOG_INCLUDE_REQUEST_CONTENT="False"; fi
if [ -z "${LOG_INCLUDE_RESPONSE_CONTENT}" ]; then export LOG_INCLUDE_RESPONSE_CONTENT="False"; fi
if [ -z "${LOG_INCLUDE_BLOCK_SYNC_MESSAGES}" ]; then export LOG_INCLUDE_BLOCK_SYNC_MESSAGES="False"; fi
if [ -z "${LOG_CONSOLE_HIGHLIGHTING}" ]; then export LOG_CONSOLE_HIGHLIGHTING="True"; fi


# --- STAGE 1: OPTIONAL PUBLIC TUNNEL VIA PINGGY ---
if [ "${ENABLE_PINGGY_TUNNEL}" = "true" ]; then
  echo "Pinggy tunnel enabled. Starting tunnel..."
  ssh -n -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null \
      -p 443 -R0:localhost:${qrdx_NODE_PORT} free.pinggy.io > /tmp/pinggy.log 2>&1 &

  echo "Waiting for Pinggy to provide a public URL..."
  COUNTER=0
  PUBLIC_ADDRESS=""
  while [ $COUNTER -lt 30 ]; do
    PUBLIC_ADDRESS=$(grep -o 'https://[a-zA-Z0-9-]*\.a\.free\.pinggy\.link' /tmp/pinggy.log | head -n 1 || true)
    if [ -n "$PUBLIC_ADDRESS" ]; then
      echo "SUCCESS: Captured public URL: ${PUBLIC_ADDRESS}"
      export qrdx_SELF_URL="${PUBLIC_ADDRESS}"
      echo "${PUBLIC_ADDRESS}" >> "${REGISTRY_FILE}"
      echo "Published public URL to registry."
      break
    fi
    sleep 1
    COUNTER=$((COUNTER+1))
  done

  if [ -z "$PUBLIC_ADDRESS" ]; then
    echo "WARNING: Could not get public URL from Pinggy. Falling back to internal URL."
    export qrdx_SELF_URL="http://${NODE_NAME}:${qrdx_NODE_PORT}"
    export ENABLE_PINGGY_TUNNEL="false"
    tail -n 50 /tmp/pinggy.log || true
  fi
else
  echo "Pinggy tunnel not enabled. Using internal URL for self."
fi

# --- STAGE 2 AND 3: BOOTSTRAP DISCOVERY WHEN REQUESTED ---
if [ "${qrdx_BOOTSTRAP_NODE}" = "discover" ]; then
  EXPECTED_URLS=1
  if [ "${ENABLE_PINGGY_TUNNEL}" = "true" ]; then
    EXPECTED_URLS=2
    echo "Discovery requested and tunneling enabled. Waiting for a second public node..."
  else
    echo "Discovery requested. Waiting for any public node to register..."
  fi

  COUNTER=0
  MAX_WAIT_ITERATIONS=60

  while [ "$(wc -l < "${REGISTRY_FILE}" 2>/dev/null || echo 0)" -lt "${EXPECTED_URLS}" ] && [ $COUNTER -lt $MAX_WAIT_ITERATIONS ]; do
    CURRENT=$(wc -l < "${REGISTRY_FILE}" 2>/dev/null || echo 0)
    echo "Waiting for public nodes... found ${CURRENT}/${EXPECTED_URLS}"
    sleep 2
    COUNTER=$((COUNTER+1))
  done

  if [ "$(wc -l < "${REGISTRY_FILE}" 2>/dev/null || echo 0)" -lt "${EXPECTED_URLS}" ]; then
    echo "WARNING: Timed out waiting for enough public nodes."
    export qrdx_BOOTSTRAP_NODE="${qrdx_SELF_URL}"
  else
    OTHER_PUBLIC_ADDRESS=$(grep -v "${qrdx_SELF_URL}" "${REGISTRY_FILE}" | head -n 1 || true)
    if [ -n "${OTHER_PUBLIC_ADDRESS}" ]; then
      export qrdx_BOOTSTRAP_NODE="${OTHER_PUBLIC_ADDRESS}"
      echo "Discovered and selected bootstrap peer: ${qrdx_BOOTSTRAP_NODE}"
    else
      echo "WARNING: Could not discover a different bootstrap peer. Falling back to self."
      export qrdx_BOOTSTRAP_NODE="${qrdx_SELF_URL}"
    fi
  fi
fi

if [ "${qrdx_BOOTSTRAP_NODE}" = "self" ]; then
  export qrdx_BOOTSTRAP_NODE="${qrdx_SELF_URL}"
fi

# --- STAGE 4: CONFIGURE AND LAUNCH ---
echo "Configuring .env file for ${NODE_NAME}..."

# Ensure SQLite database directory exists
DB_DIR=$(dirname "${QRDX_DATABASE_PATH}")
mkdir -p "${DB_DIR}"
echo "SQLite database directory ensured: ${DB_DIR}"

cat << EOF > /app/.env
qrdx_NODE_HOST=${qrdx_NODE_HOST}
qrdx_NODE_PORT=${qrdx_NODE_PORT}
qrdx_SELF_URL=${qrdx_SELF_URL}
qrdx_BOOTSTRAP_NODE=${qrdx_BOOTSTRAP_NODE}

QRDX_DATABASE_PATH=${QRDX_DATABASE_PATH}

LOG_LEVEL=${LOG_LEVEL}
LOG_FORMAT=${LOG_FORMAT}
LOG_DATE_FORMAT=${LOG_DATE_FORMAT}
LOG_CONSOLE_HIGHLIGHTING=${LOG_CONSOLE_HIGHLIGHTING}
LOG_INCLUDE_REQUEST_CONTENT=${LOG_INCLUDE_REQUEST_CONTENT}
LOG_INCLUDE_RESPONSE_CONTENT=${LOG_INCLUDE_RESPONSE_CONTENT}
LOG_INCLUDE_BLOCK_SYNC_MESSAGES=${LOG_INCLUDE_BLOCK_SYNC_MESSAGES}
EOF

echo "Generated .env file:"
cat /app/.env
echo "----------------------------------------"

# Launch the qrdx Node
echo "Starting qrdx node on 0.0.0.0:${qrdx_NODE_PORT}..."
exec python /app/run_node.py
