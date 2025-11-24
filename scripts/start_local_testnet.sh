#!/bin/bash
#
# QRDX Local Testnet Node Launcher
# 
# This script starts a local QRDX testnet node with:
# - Fresh genesis state (150 validators)
# - Temporary data directory
# - QR-PoS consensus (2-second block time)
# - Automatic cleanup on exit
#
# Usage:
#   ./scripts/start_local_testnet.sh [OPTIONS]
#
# Options:
#   --port PORT          P2P listening port (default: 30303)
#   --rpc-port PORT      HTTP RPC port (default: 8545)
#   --ws-port PORT       WebSocket RPC port (default: 8546)
#   --network-id ID      Network ID (default: 1337)
#   --validator-index N  Run as validator N (0-149, default: 0)
#   --no-cleanup         Don't delete data on exit
#   --help               Show this help message

set -e  # Exit on error

# Color output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Default configuration
P2P_PORT=30303
RPC_PORT=8545
WS_PORT=8546
NETWORK_ID=1337
VALIDATOR_INDEX=0
CLEANUP=true
DATA_DIR=""

# Get script directory
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

# Parse command line arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        --port)
            P2P_PORT="$2"
            shift 2
            ;;
        --rpc-port)
            RPC_PORT="$2"
            shift 2
            ;;
        --ws-port)
            WS_PORT="$2"
            shift 2
            ;;
        --network-id)
            NETWORK_ID="$2"
            shift 2
            ;;
        --validator-index)
            VALIDATOR_INDEX="$2"
            shift 2
            ;;
        --no-cleanup)
            CLEANUP=false
            shift
            ;;
        --help)
            echo "QRDX Local Testnet Node Launcher"
            echo ""
            echo "Usage: $0 [OPTIONS]"
            echo ""
            echo "Options:"
            echo "  --port PORT          P2P listening port (default: 30303)"
            echo "  --rpc-port PORT      HTTP RPC port (default: 8545)"
            echo "  --ws-port PORT       WebSocket RPC port (default: 8546)"
            echo "  --network-id ID      Network ID (default: 1337)"
            echo "  --validator-index N  Run as validator N (0-149, default: 0)"
            echo "  --no-cleanup         Don't delete data on exit"
            echo "  --help               Show this help message"
            echo ""
            echo "Examples:"
            echo "  $0                                    # Start node with defaults"
            echo "  $0 --validator-index 5                # Run as validator 5"
            echo "  $0 --rpc-port 8555 --no-cleanup      # Custom RPC port, keep data"
            exit 0
            ;;
        *)
            echo -e "${RED}Error: Unknown option: $1${NC}"
            echo "Use --help for usage information"
            exit 1
            ;;
    esac
done

# Validate validator index
if [ "$VALIDATOR_INDEX" -lt 0 ] || [ "$VALIDATOR_INDEX" -gt 149 ]; then
    echo -e "${RED}Error: Validator index must be between 0 and 149${NC}"
    exit 1
fi

# Create temporary data directory
DATA_DIR=$(mktemp -d -t qrdx-testnet-XXXXXX)

echo -e "${BLUE}╔════════════════════════════════════════════════════════════╗${NC}"
echo -e "${BLUE}║         QRDX Local Testnet Node                           ║${NC}"
echo -e "${BLUE}╚════════════════════════════════════════════════════════════╝${NC}"
echo ""
echo -e "${GREEN}Configuration:${NC}"
echo -e "  Chain:           QRDX Testnet"
echo -e "  Network ID:      ${NETWORK_ID}"
echo -e "  Consensus:       QR-PoS (2-second blocks)"
echo -e "  Validators:      150 (you are validator ${VALIDATOR_INDEX})"
echo -e "  Data Directory:  ${DATA_DIR}"
echo -e "  P2P Port:        ${P2P_PORT}"
echo -e "  HTTP RPC:        http://localhost:${RPC_PORT}"
echo -e "  WebSocket RPC:   ws://localhost:${WS_PORT}"
echo ""

# Cleanup function
cleanup() {
    echo ""
    echo -e "${YELLOW}Shutting down node...${NC}"
    
    # Kill trinity process if running
    if [ ! -z "$TRINITY_PID" ]; then
        kill $TRINITY_PID 2>/dev/null || true
        wait $TRINITY_PID 2>/dev/null || true
    fi
    
    # Remove data directory
    if [ "$CLEANUP" = true ] && [ -d "$DATA_DIR" ]; then
        echo -e "${YELLOW}Cleaning up data directory: ${DATA_DIR}${NC}"
        rm -rf "$DATA_DIR"
        echo -e "${GREEN}✓ Data directory removed${NC}"
    else
        echo -e "${BLUE}Data directory preserved: ${DATA_DIR}${NC}"
    fi
    
    echo -e "${GREEN}✓ Node stopped${NC}"
}

# Register cleanup on exit
trap cleanup EXIT INT TERM

# Check if trinity is installed
if ! command -v trinity &> /dev/null; then
    echo -e "${YELLOW}Trinity not found in PATH, attempting to use from project...${NC}"
    
    # Try to use trinity from the project
    cd "$PROJECT_ROOT"
    
    # Activate virtual environment if it exists
    if [ -d "venv" ]; then
        echo -e "${BLUE}Activating virtual environment...${NC}"
        source venv/bin/activate
    elif [ -d ".venv" ]; then
        echo -e "${BLUE}Activating virtual environment...${NC}"
        source .venv/bin/activate
    fi
    
    # Try to run trinity via Python module
    if python3 -c "import trinity" 2>/dev/null; then
        TRINITY_CMD="python3 -m trinity"
        echo -e "${GREEN}✓ Using trinity Python module${NC}"
    else
        echo -e "${RED}Error: Trinity not installed${NC}"
        echo ""
        echo "Please install QRDX Chain first:"
        echo "  cd $PROJECT_ROOT"
        echo "  pip install -e ."
        exit 1
    fi
else
    TRINITY_CMD="trinity"
    echo -e "${GREEN}✓ Using system trinity${NC}"
fi

echo ""
echo -e "${BLUE}Initializing QRDX testnet...${NC}"

# Create genesis configuration
GENESIS_FILE="${DATA_DIR}/genesis.json"
cat > "$GENESIS_FILE" << EOF
{
  "config": {
    "chainId": ${NETWORK_ID},
    "qrdxBlock": 0
  },
  "nonce": "0x0",
  "timestamp": "0x0",
  "extraData": "0x5152445820546573746e6574204765",
  "gasLimit": "0x2faf080",
  "difficulty": "0x0",
  "mixHash": "0x0000000000000000000000000000000000000000000000000000000000000000",
  "coinbase": "0x0000000000000000000000000000000000000000",
  "alloc": {
    "0x0000000000000000000000000000000000000001": {
      "balance": "1000000000000000000000000"
    }
  }
}
EOF

echo -e "${GREEN}✓ Genesis configuration created${NC}"

# Generate validator keypair for this node
NODEKEY_FILE="${DATA_DIR}/nodekey"
openssl rand -hex 32 > "$NODEKEY_FILE"
echo -e "${GREEN}✓ Node key generated${NC}"

# Start Trinity node
echo ""
echo -e "${BLUE}Starting QRDX node...${NC}"
echo -e "${YELLOW}Press Ctrl+C to stop the node${NC}"
echo ""
echo -e "${BLUE}════════════════════════════════════════════════════════════${NC}"
echo ""

# Build Trinity command
TRINITY_ARGS=(
    --data-dir "$DATA_DIR"
    --network-id "$NETWORK_ID"
    --port "$P2P_PORT"
    --nodekey "$(cat $NODEKEY_FILE)"
    --genesis "$GENESIS_FILE"
)

# Add RPC options
TRINITY_ARGS+=(
    --enable-http
    --http-port "$RPC_PORT"
    --http-api eth,net,web3,qrdx
)

# Add WebSocket options
TRINITY_ARGS+=(
    --enable-ws
    --ws-port "$WS_PORT"
    --ws-api eth,net,web3,qrdx
)

# Add validator options if applicable
if [ "$VALIDATOR_INDEX" -ge 0 ]; then
    TRINITY_ARGS+=(
        --validator
        --validator-index "$VALIDATOR_INDEX"
    )
fi

# Run Trinity
cd "$PROJECT_ROOT"
$TRINITY_CMD "${TRINITY_ARGS[@]}" &
TRINITY_PID=$!

# Wait for node to start
echo -e "${BLUE}Waiting for node to start...${NC}"
sleep 3

# Check if process is still running
if ! kill -0 $TRINITY_PID 2>/dev/null; then
    echo -e "${RED}Error: Node failed to start${NC}"
    echo ""
    echo "Check the logs above for errors."
    echo ""
    echo "Common issues:"
    echo "  - Port already in use (try different --port or --rpc-port)"
    echo "  - Missing dependencies (run: pip install -e .)"
    echo "  - Invalid configuration"
    exit 1
fi

echo -e "${GREEN}✓ Node is running (PID: ${TRINITY_PID})${NC}"
echo ""
echo -e "${GREEN}╔════════════════════════════════════════════════════════════╗${NC}"
echo -e "${GREEN}║  QRDX Testnet Node Running                                ║${NC}"
echo -e "${GREEN}╚════════════════════════════════════════════════════════════╝${NC}"
echo ""
echo -e "${BLUE}Connection Details:${NC}"
echo -e "  HTTP RPC:   ${GREEN}http://localhost:${RPC_PORT}${NC}"
echo -e "  WebSocket:  ${GREEN}ws://localhost:${WS_PORT}${NC}"
echo -e "  Network ID: ${GREEN}${NETWORK_ID}${NC}"
echo ""
echo -e "${BLUE}Test the connection:${NC}"
echo -e "  ${YELLOW}curl -X POST http://localhost:${RPC_PORT} \\${NC}"
echo -e "  ${YELLOW}  -H 'Content-Type: application/json' \\${NC}"
echo -e "  ${YELLOW}  -d '{\"jsonrpc\":\"2.0\",\"method\":\"eth_blockNumber\",\"params\":[],\"id\":1}'${NC}"
echo ""
echo -e "${BLUE}Validator Status:${NC}"
echo -e "  Index:      ${GREEN}${VALIDATOR_INDEX}${NC}"
echo -e "  Status:     ${GREEN}Active${NC}"
echo -e "  Proposing:  ${GREEN}Yes (every ~300 seconds)${NC}"
echo ""
echo -e "${YELLOW}Press Ctrl+C to stop the node and cleanup...${NC}"
echo ""
echo -e "${BLUE}════════════════════════════════════════════════════════════${NC}"

# Wait for Trinity process
wait $TRINITY_PID
