#!/bin/bash
#
# QRDX Multi-Node Local Testnet Setup
#
# Starts multiple QRDX nodes for testing P2P networking and consensus.
# Each node runs as an independent validator with its own database.
#
# Usage: ./start_multi_node_testnet.sh [num_nodes] [--keep]
#   num_nodes: Number of nodes to start (default: 3)
#   --keep:    Keep logs after shutdown (default: cleanup)
#

set -e

# Get script directory
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Parse arguments
NUM_NODES=3
KEEP_LOGS=false

for arg in "$@"; do
    if [[ "$arg" == "--keep" ]]; then
        KEEP_LOGS=true
    elif [[ "$arg" =~ ^[0-9]+$ ]]; then
        NUM_NODES="$arg"
    fi
done

# Configuration
# Use random ports to avoid conflicts
BASE_PORT=$((30400 + RANDOM % 100))
BASE_RPC_PORT=$((9000 + RANDOM % 1000))
BASE_WS_PORT=$((BASE_RPC_PORT + 1000))
NETWORK_ID=1337
CHAIN_ID=1337

echo "Using P2P base port: $BASE_PORT"
echo "Using RPC base port: $BASE_RPC_PORT"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

# Cleanup function
cleanup() {
    echo ""
    echo -e "${YELLOW}Shutting down all nodes...${NC}"
    
    # Kill all trinity processes
    pkill -f "trinity --network-id ${NETWORK_ID}" || true
    
    if [ "$KEEP_LOGS" = true ]; then
        # Keep logs
        echo ""
        echo -e "${CYAN}Logs preserved at:${NC}"
        for i in $(seq 0 $((NUM_NODES - 1))); do
            DATA_DIR="/tmp/qrdx-node-${i}"
            if [ -f "$DATA_DIR/trinity.log" ]; then
                echo "  Node ${i}: $DATA_DIR/trinity.log"
            fi
        done
        
        echo ""
        echo -e "${YELLOW}To cleanup logs manually, run:${NC}"
        echo "  rm -rf /tmp/qrdx-node-*"
        
        echo -e "${GREEN}✓ All nodes stopped (logs preserved)${NC}"
    else
        # Clean up data directories
        for i in $(seq 0 $((NUM_NODES - 1))); do
            DATA_DIR="/tmp/qrdx-node-${i}"
            if [ -d "$DATA_DIR" ]; then
                rm -rf "$DATA_DIR"
            fi
        done
        
        echo -e "${GREEN}✓ All nodes stopped and cleaned up${NC}"
    fi
    
    exit 0
}

# Set up trap for cleanup on exit
trap cleanup SIGINT SIGTERM EXIT

# Header
echo "╔════════════════════════════════════════════════════════════╗"
echo "║         QRDX Multi-Node Local Testnet                     ║"
echo "╚════════════════════════════════════════════════════════════╝"
echo ""

# Validate num nodes
if [ "$NUM_NODES" -lt 2 ]; then
    echo -e "${RED}Error: Must have at least 2 nodes${NC}"
    exit 1
fi

if [ "$NUM_NODES" -gt 10 ]; then
    echo -e "${RED}Error: Maximum 10 nodes supported${NC}"
    exit 1
fi

echo -e "${CYAN}Configuration:${NC}"
echo "  Nodes:           ${NUM_NODES}"
echo "  Chain:           QRDX Testnet"
echo "  Network ID:      ${NETWORK_ID}"
echo "  Consensus:       QR-PoS (2-second blocks)"
echo "  Base P2P Port:   ${BASE_PORT}"
echo "  Base RPC Port:   ${BASE_RPC_PORT}"
echo "  Base WS Port:    ${BASE_WS_PORT}"
echo ""

# Check if trinity is available
if ! command -v trinity &> /dev/null; then
    echo -e "${RED}✗ Trinity not found${NC}"
    echo "  Please install trinity or ensure it's in your PATH"
    exit 1
fi

echo -e "${GREEN}✓ Using trinity: $(which trinity)${NC}"
echo ""

# Generate genesis configuration
echo -e "${CYAN}Generating genesis configuration...${NC}"

# Create a shared genesis file with RECENT fixed timestamp
# Using timestamp from ~10 minutes ago to keep slot numbers reasonable
GENESIS_FILE="/tmp/qrdx-multi-node-genesis.json"
CURRENT_TIME=$(date +%s)
GENESIS_TS=$((CURRENT_TIME - 600))  # 10 minutes ago
GENESIS_TIMESTAMP=$(printf "0x%x" $GENESIS_TS)

cat > "$GENESIS_FILE" << EOF
{
  "version": "1",
  "params": {
    "chainId": "0x539",
    "miningMethod": "NoProof",
    "frontierForkBlock": "0x0",
    "homesteadForkBlock": "0x0",
    "EIP150ForkBlock": "0x0",
    "EIP158ForkBlock": "0x0",
    "byzantiumForkBlock": "0x0",
    "constantinopleForkBlock": "0x0",
    "petersburgForkBlock": "0x0",
    "istanbulForkBlock": "0x0"
  },
  "genesis": {
    "nonce": "0x0000000000000000",
    "difficulty": "0x0",
    "author": "0x0000000000000000000000000000000000000000",
    "timestamp": "${GENESIS_TIMESTAMP}",
    "extraData": "0x5152445820546573746e6574204765",
    "gasLimit": "0x2faf080"
  },
  "accounts": {
    "0x0000000000000000000000000000000000000001": {
      "balance": "0xd3c21bcecceda1000000"
    },
    "0x1000000000000000000000000000000000000001": {
      "balance": "0xd3c21bcecceda1000000"
    }
  }
}
EOF

echo -e "${GREEN}✓ Genesis configuration created${NC}"

# Generate validator keystores
echo ""
echo -e "${CYAN}Generating validator keystores...${NC}"
echo ""

# Set keystore directory
KEYSTORE_DIR="/tmp/qrdx-validator-keys"

# Use default testnet password if not set
if [ -z "$QRDX_KEYSTORE_PASSWORD" ]; then
    export QRDX_KEYSTORE_PASSWORD="testnet-insecure-password"
    echo -e "${YELLOW}⚠️  Using default testnet password (INSECURE - for testing only!)${NC}"
fi

# Check if keystores already exist with correct number
EXISTING_KEYSTORES=$(find "$KEYSTORE_DIR" -name "*.json" 2>/dev/null | wc -l)
if [ "$EXISTING_KEYSTORES" -eq "$NUM_NODES" ]; then
    echo -e "${GREEN}✓ Found ${NUM_NODES} existing keystores in ${KEYSTORE_DIR}${NC}"
else
    # Generate new keystores
    echo -e "${CYAN}Generating ${NUM_NODES} validator keystores...${NC}"
    
    # Remove old keystores
    rm -rf "$KEYSTORE_DIR"
    mkdir -p "$KEYSTORE_DIR"
    
    # Generate keystores using Python script
    python3 "${SCRIPT_DIR}/generate_validator_keys.py" \
        "$NUM_NODES" \
        --keystore-dir "$KEYSTORE_DIR" \
        --password-env \
        2>&1 | grep -E "(Generating|✓|Validator [0-9]+:|Public Key:)" || true
    
    echo -e "${GREEN}✓ Validator keystores generated${NC}"
fi

# Export keystore settings for Trinity
export QRDX_KEYSTORE_DIR="$KEYSTORE_DIR"
export QRDX_NUM_VALIDATORS="$NUM_NODES"

echo ""

# Generate node keys and start nodes
echo -e "${CYAN}Starting nodes...${NC}"
echo ""

# Clean old data directories to ensure fresh genesis
for i in $(seq 0 $((NUM_NODES - 1))); do
    DATA_DIR="/tmp/qrdx-node-${i}"
    if [ -d "$DATA_DIR" ]; then
        echo -e "${YELLOW}Cleaning old data directory: ${DATA_DIR}${NC}"
        rm -rf "$DATA_DIR"
    fi
done
echo ""

NODE_PIDS=()
ENODES=()

for i in $(seq 0 $((NUM_NODES - 1))); do
    NODE_PORT=$((BASE_PORT + i))
    RPC_PORT=$((BASE_RPC_PORT + i))
    WS_PORT=$((BASE_WS_PORT + i))
    DATA_DIR="/tmp/qrdx-node-${i}"
    
    echo -e "${BLUE}Node ${i}:${NC}"
    
    # Create data directory structure
    mkdir -p "$DATA_DIR"/{logs-eth1,mainnet-eth1,ipcs-eth1}
    
    # Generate node key (32 bytes for private key, written as raw binary)
    openssl rand 32 > "${DATA_DIR}/nodekey"
    
    # Derive enode public key from nodekey using secp256k1
    ENODE_PUBKEY=$(python3 "${SCRIPT_DIR}/get_enode_from_nodekey.py" "${DATA_DIR}/nodekey")
    ENODE="enode://${ENODE_PUBKEY}@127.0.0.1:${NODE_PORT}"
    ENODES+=("$ENODE")
    
    echo "  Data Directory:  ${DATA_DIR}"
    echo "  P2P Port:        ${NODE_PORT}"
    echo "  HTTP RPC:        http://localhost:${RPC_PORT}"
    echo "  WebSocket RPC:   ws://localhost:${WS_PORT}"
    echo "  Validator Index: ${i}"
    
    # Copy genesis file
    cp "$GENESIS_FILE" "${DATA_DIR}/genesis.json"
    
    # Build static peers list (connect to previous nodes)
    STATIC_PEERS=""
    if [ $i -gt 0 ]; then
        # Connect to node 0 (bootstrap node)
        STATIC_PEERS="--preferred-node ${ENODES[0]}"
        
        # Also connect to previous node if not node 1
        if [ $i -gt 1 ]; then
            PREV_NODE=$((i - 1))
            STATIC_PEERS="${STATIC_PEERS} --preferred-node ${ENODES[$PREV_NODE]}"
        fi
    fi
    
    # Start Trinity node
    LOG_FILE="${DATA_DIR}/trinity.log"
    
    nohup trinity \
        --data-dir "$DATA_DIR" \
        --network-id $NETWORK_ID \
        --port $NODE_PORT \
        --nodekey "${DATA_DIR}/nodekey" \
        --genesis "${DATA_DIR}/genesis.json" \
        --sync-mode full \
        --disable-networkdb-component \
        --enable-http-apis=eth,net,web3 \
        --http-listen-address=127.0.0.1 \
        --http-port=$RPC_PORT \
        $STATIC_PEERS \
        > "$LOG_FILE" 2>&1 &
    
    NODE_PID=$!
    NODE_PIDS+=($NODE_PID)
    
    echo "  PID:             ${NODE_PID}"
    echo ""
    
    # Wait a bit between node starts to avoid port conflicts
    sleep 2
done

echo -e "${GREEN}✓ All nodes started${NC}"
echo ""

# Wait for nodes to initialize
echo -e "${CYAN}Waiting for nodes to initialize...${NC}"
sleep 10

# Check node status
echo ""
echo "╔════════════════════════════════════════════════════════════╗"
echo "║  QRDX Multi-Node Testnet Running                          ║"
echo "╚════════════════════════════════════════════════════════════╝"
echo ""

# Display node summary
echo -e "${CYAN}Active Nodes:${NC}"
for i in $(seq 0 $((NUM_NODES - 1))); do
    NODE_PID=${NODE_PIDS[$i]}
    RPC_PORT=$((BASE_RPC_PORT + i))
    
    if ps -p $NODE_PID > /dev/null 2>&1; then
        echo -e "  ${GREEN}✓${NC} Node ${i} (PID: ${NODE_PID}) - http://localhost:${RPC_PORT}"
    else
        echo -e "  ${RED}✗${NC} Node ${i} (PID: ${NODE_PID}) - ${RED}NOT RUNNING${NC}"
    fi
done

echo ""
echo -e "${CYAN}Test Connection (Node 0):${NC}"
echo "  curl -X POST http://localhost:${BASE_RPC_PORT} \\"
echo "    -H 'Content-Type: application/json' \\"
echo "    -d '{\"jsonrpc\":\"2.0\",\"method\":\"eth_blockNumber\",\"params\":[],\"id\":1}'"
echo ""

echo -e "${CYAN}View Node Logs:${NC}"
for i in $(seq 0 $((NUM_NODES - 1))); do
    echo "  Node ${i}: tail -f /tmp/qrdx-node-${i}/trinity.log"
done

echo ""
echo -e "${CYAN}Network Topology:${NC}"
echo "  Node 0 (Bootstrap) ← All other nodes connect to this"
if [ "$NUM_NODES" -gt 2 ]; then
    echo "  Nodes 2+ also connect to their previous node"
fi

echo ""
echo -e "${YELLOW}Press Ctrl+C to stop all nodes and cleanup...${NC}"
echo ""
echo "════════════════════════════════════════════════════════════"

# Check if nodes crash immediately
sleep 3
IMMEDIATE_FAILURES=0
for i in $(seq 0 $((NUM_NODES - 1))); do
    NODE_PID=${NODE_PIDS[$i]}
    if ! ps -p $NODE_PID > /dev/null 2>&1; then
        echo -e "${RED}[$(date '+%H:%M:%S')] Node ${i} (PID: ${NODE_PID}) crashed on startup!${NC}"
        echo -e "${YELLOW}Last 50 lines of log:${NC}"
        tail -50 "/tmp/qrdx-node-${i}/trinity.log" 2>/dev/null || echo "  (no log file found)"
        echo ""
        IMMEDIATE_FAILURES=$((IMMEDIATE_FAILURES + 1))
    fi
done

if [ $IMMEDIATE_FAILURES -gt 0 ]; then
    echo -e "${RED}${IMMEDIATE_FAILURES}/${NUM_NODES} nodes failed to start. Check logs above.${NC}"
    exit 1
fi

echo -e "${GREEN}All nodes started successfully!${NC}"
echo ""

# Monitor nodes
while true; do
    sleep 30
    
    # Check if any node died
    DEAD_NODES=0
    for i in $(seq 0 $((NUM_NODES - 1))); do
        NODE_PID=${NODE_PIDS[$i]}
        if ! ps -p $NODE_PID > /dev/null 2>&1; then
            echo -e "${RED}[$(date '+%H:%M:%S')] Node ${i} (PID: ${NODE_PID}) has stopped${NC}"
            DEAD_NODES=$((DEAD_NODES + 1))
        fi
    done
    
    # If more than half the nodes are dead, exit
    if [ $DEAD_NODES -gt $((NUM_NODES / 2)) ]; then
        echo -e "${RED}Too many nodes have stopped. Exiting...${NC}"
        exit 1
    fi
    
    # Show status update
    ALIVE_NODES=$((NUM_NODES - DEAD_NODES))
    echo -e "${CYAN}[$(date '+%H:%M:%S')] Status: ${GREEN}${ALIVE_NODES}/${NUM_NODES} nodes running${NC}"
done
