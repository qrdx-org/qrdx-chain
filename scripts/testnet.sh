#!/bin/bash
#
# QRDX Local Testnet Manager
#
# Professional testnet deployment script for QRDX Chain.
# Creates a complete local testnet with configurable nodes and validators.
#
# Usage:
#   ./scripts/testnet.sh start [--nodes N] [--validators V]
#   ./scripts/testnet.sh stop
#   ./scripts/testnet.sh status
#   ./scripts/testnet.sh clean
#   ./scripts/testnet.sh logs [node_id]
#
# Author: QRDX Development Team
# License: MIT

set -euo pipefail

# =============================================================================
# CONFIGURATION
# =============================================================================

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"
TESTNET_DIR="${PROJECT_DIR}/testnet"
LOGS_DIR="${TESTNET_DIR}/logs"
DATA_DIR="${TESTNET_DIR}/data"
WALLETS_DIR="${TESTNET_DIR}/wallets"
CONFIG_DIR="${TESTNET_DIR}/configs"

# Default configuration
DEFAULT_NODES=4
DEFAULT_VALIDATORS=2
DEFAULT_BASE_PORT=3007
DEFAULT_GENESIS_BALANCE=1000000  # 1M QRDX per validator

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color
BOLD='\033[1m'

# =============================================================================
# UTILITY FUNCTIONS
# =============================================================================

log_info() {
    echo -e "${BLUE}[INFO]${NC} $*"
}

log_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $*"
}

log_warn() {
    echo -e "${YELLOW}[WARN]${NC} $*"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $*"
}

log_step() {
    echo -e "\n${BOLD}${CYAN}==>${NC} ${BOLD}$*${NC}\n"
}

command_exists() {
    command -v "$1" >/dev/null 2>&1
}

check_dependencies() {
    log_step "Checking dependencies"
    
    local missing_deps=()
    
    if ! command_exists python3; then
        missing_deps+=("python3")
    fi
    
    if ! command_exists jq; then
        missing_deps+=("jq")
    fi
    
    if [ ${#missing_deps[@]} -ne 0 ]; then
        log_error "Missing dependencies: ${missing_deps[*]}"
        log_info "Install with: sudo apt-get install ${missing_deps[*]}"
        return 1
    fi
    
    log_success "All dependencies satisfied"
    return 0
}

# =============================================================================
# WALLET GENERATION
# =============================================================================

generate_validator_wallet() {
    local validator_id=$1
    local wallet_path="${WALLETS_DIR}/validator_${validator_id}.json"
    local password="testnet_validator_${validator_id}"
    
    log_info "Generating PQ wallet for validator ${validator_id}..." >&2
    
    # Create wallet using QRDX crypto module (suppress liboqs warnings)
    OQS_FAULTHANDLER=0 PYTHONWARNINGS=ignore python3 -W ignore 2>/dev/null << EOF
import sys, os, json, warnings
warnings.filterwarnings('ignore')
sys.path.insert(0, '${PROJECT_DIR}')

from qrdx.crypto.pq.dilithium import generate_keypair
from qrdx.crypto.address import public_key_to_address, AddressType

# Generate PQ keypair (ML-DSA-65 / Dilithium3)
private_key, public_key = generate_keypair()

# Generate address from public key bytes
address = public_key_to_address(public_key.to_bytes(), AddressType.POST_QUANTUM)

# Create wallet structure
wallet = {
    "version": "2.0",
    "type": "pq",
    "algorithm": "dilithium3",
    "address": address,
    "public_key": public_key.to_hex(),
    "private_key": private_key.to_hex(),
    "label": "Validator ${validator_id}",
    "created": "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
}

# Save wallet
os.makedirs(os.path.dirname('${wallet_path}'), exist_ok=True)
with open('${wallet_path}', 'w') as f:
    json.dump(wallet, f, indent=2)

# Output address for shell script (stdout only)
print(address)
EOF
}

get_wallet_address() {
    local wallet_path=$1
    python3 -c "import json; print(json.load(open('${wallet_path}'))['address'])"
}

get_wallet_pubkey() {
    local wallet_path=$1
    python3 -c "import json; print(json.load(open('${wallet_path}'))['public_key'])"
}

generate_master_controller_wallet() {
    local wallet_path="${WALLETS_DIR}/master_controller.json"
    
    log_info "Generating Master Controller PQ wallet..."
    
    # Create master controller wallet (suppress liboqs warnings)
    PYTHONWARNINGS=ignore python3 -W ignore 2>/dev/null << EOF
import sys, os, json, warnings
warnings.filterwarnings('ignore')
os.environ['OQS_FAULTHANDLER'] = '0'
sys.path.insert(0, '${PROJECT_DIR}')

from qrdx.crypto.pq.dilithium import PQPrivateKey

# Generate PQ keypair (ML-DSA-65 / Dilithium3)
private_key = PQPrivateKey.generate()
public_key = private_key.public_key
address = public_key.to_address()

# Create wallet structure
wallet = {
    "version": "2.0",
    "type": "pq",
    "algorithm": "dilithium3",
    "address": address,
    "public_key": public_key.to_hex(),
    "private_key": private_key.to_hex(),
    "label": "Master Controller (System Wallets)",
    "created": "$(date -u +%Y-%m-%dT%H:%M:%SZ)",
    "purpose": "Controls all system wallets (treasury, grants, etc.)"
}

# Save wallet
os.makedirs(os.path.dirname('${wallet_path}'), exist_ok=True)
with open('${wallet_path}', 'w') as f:
    json.dump(wallet, f, indent=2)

# Output address for shell script (stdout only)
print(address)
EOF
}

# =============================================================================
# GENESIS CREATION
# =============================================================================

create_genesis_config() {
    local num_validators=$1
    local genesis_file="${TESTNET_DIR}/genesis_config.json"
    
    log_step "Creating genesis configuration"
    
    # Get master controller wallet address
    local controller_wallet_path="${WALLETS_DIR}/master_controller.json"
    local controller_address=$(get_wallet_address "$controller_wallet_path")
    
    log_info "Master Controller: ${controller_address}"
    log_info "  (Controls all 10 system wallets with 75M QRDX)"
    echo
    
    # Collect validator addresses
    local validator_addresses=()
    local validator_pubkeys=()
    
    for i in $(seq 0 $((num_validators - 1))); do
        local wallet_path="${WALLETS_DIR}/validator_${i}.json"
        local address=$(get_wallet_address "$wallet_path")
        local pubkey=$(get_wallet_pubkey "$wallet_path")
        
        validator_addresses+=("$address")
        validator_pubkeys+=("$pubkey")
        
        log_info "Validator $i: ${address:0:20}..."
    done
    
    # Create genesis configuration (suppress liboqs warnings, capture output)
    local genesis_output
    genesis_output=$(OQS_FAULTHANDLER=0 PYTHONWARNINGS=ignore python3 -W ignore 2>/dev/null << EOF
import sys, os, json, warnings
warnings.filterwarnings('ignore')
from decimal import Decimal
sys.path.insert(0, '${PROJECT_DIR}')

# Redirect all logging to stderr so JSON comes cleanly on stdout
import logging
logging.basicConfig(stream=sys.stderr)

from qrdx.validator.genesis import GenesisCreator, GenesisConfig

# Validator data - properly format as Python lists with commas
validator_addresses = [$(printf "'%s'," "${validator_addresses[@]}" | sed 's/,$//')] 
validator_pubkeys = [$(printf "'%s'," "${validator_pubkeys[@]}" | sed 's/,$//')]

# Master controller address
controller_address = '${controller_address}'

# Create genesis config with system wallets
config = GenesisConfig(
    chain_id=9999,
    network_name="qrdx-testnet-local",
    min_genesis_validators=1,
    initial_supply=Decimal("100000000"),  # 100M QRDX
    system_wallet_controller=controller_address,
    enable_system_wallets=True,
)

# Create prefunded accounts for validators
pre_allocations = {}
for i, addr in enumerate(validator_addresses):
    pre_allocations[addr] = Decimal("${DEFAULT_GENESIS_BALANCE}")
    config.pre_allocations[addr] = Decimal("${DEFAULT_GENESIS_BALANCE}")

# Add test account for contract deployment (derived from private key 0x01)
test_account = "0x7E5F4552091A69125d5DfCb7b8C2659029395Bdf"
config.pre_allocations[test_account] = Decimal("1000000000")  # 1B QRDX for testing

creator = GenesisCreator(config)

# Add validators
for i, (addr, pubkey) in enumerate(zip(validator_addresses, validator_pubkeys)):
    stake = Decimal("100000")  # 100K QRDX stake
    creator.add_validator(addr, pubkey, stake)

# Create genesis
state, block = creator.create_genesis()

# Export
creator.export_genesis(state, block, '${genesis_file}')

print(json.dumps({
    'genesis_hash': block.block_hash,
    'state_root': state.state_root,
    'validators': len(state.validators),
    'system_wallets': len(state.system_wallets),
    'system_controller': state.system_wallet_controller,
    'total_system_allocation': state.total_system_wallets,
    'total_prefunded': str(sum(Decimal(v) for v in config.pre_allocations.values()))
}))
EOF
    )

    # Parse and display genesis summary
    if [ -n "$genesis_output" ]; then
        # Extract the JSON line (last line that starts with {)
        local genesis_json
        genesis_json=$(echo "$genesis_output" | grep '^{' | tail -1)
        if [ -n "$genesis_json" ] && command_exists jq; then
            local genesis_hash validators sys_wallets total_prefunded
            genesis_hash=$(echo "$genesis_json" | jq -r '.genesis_hash // "unknown"')
            validators=$(echo "$genesis_json" | jq -r '.validators // 0')
            sys_wallets=$(echo "$genesis_json" | jq -r '.system_wallets // 0')
            total_prefunded=$(echo "$genesis_json" | jq -r '.total_prefunded // "0"')
            log_info "Genesis hash: ${genesis_hash:0:16}..."
            log_info "Validators: ${validators}, System wallets: ${sys_wallets}"
            log_info "Total prefunded: ${total_prefunded} QRDX"
        fi
    fi

    log_success "Genesis configuration created: ${genesis_file}"
}

# =============================================================================
# DATABASE SETUP
# =============================================================================

setup_databases() {
    local num_nodes=$1
    
    log_step "Setting up SQLite databases"
    
    # Create database directory
    local db_dir="${TESTNET_DIR}/databases"
    mkdir -p "${db_dir}"
    
    # Create SQLite database for each node
    for i in $(seq 0 $((num_nodes - 1))); do
        local db_file="${db_dir}/node${i}.db"
        log_info "Creating SQLite database: ${db_file}"
        
        # Remove existing database for clean restart
        rm -f "${db_file}"
        
        # Create new empty database file
        touch "${db_file}"
        
        log_success "Database created: ${db_file}"
    done
    
    log_success "All SQLite databases created"
}

# =============================================================================
# NODE CONFIGURATION
# =============================================================================

create_node_config() {
    local node_id=$1
    local total_nodes=$2
    local is_bootstrap=$3
    local is_validator=$4
    local validator_id=${5:-}
    
    local node_port=$((DEFAULT_BASE_PORT + node_id))
    local rpc_port=$((8545 + node_id))
    local ws_port=$((8546 + node_id))
    local node_dir="${DATA_DIR}/node${node_id}"
    local config_file="${CONFIG_DIR}/node${node_id}.env"
    
    mkdir -p "$node_dir"
    
    # Determine bootstrap nodes
    local bootstrap_nodes=""
    if [ "$is_bootstrap" = false ]; then
        # Point to the bootstrap node (node 0)
        bootstrap_nodes="http://127.0.0.1:${DEFAULT_BASE_PORT}"
    fi
    
    # Create per-node identity directory
    local key_dir="${DATA_DIR}/node${node_id}/keys"
    mkdir -p "$key_dir"
    
    # Create .env file
    cat > "$config_file" << EOF
# QRDX Testnet Node ${node_id} Configuration
# Generated: $(date -u +%Y-%m-%dT%H:%M:%SZ)

# Node identification
QRDX_NODE_ID=testnet-node-${node_id}
QRDX_NETWORK_NAME=qrdx-testnet-local
QRDX_CHAIN_ID=9999

# Network settings
QRDX_NODE_HOST=127.0.0.1
QRDX_NODE_PORT=${node_port}
QRDX_SELF_URL=http://127.0.0.1:${node_port}

# Bootstrap configuration
QRDX_BOOTSTRAP_NODE=${bootstrap_nodes}
QRDX_BOOTSTRAP_NODES=${bootstrap_nodes}

# Database (SQLite)
QRDX_DATABASE_PATH=${TESTNET_DIR}/databases/node${node_id}.db

# Per-node identity key directory (avoids key collision in multi-node testnet)
QRDX_NODE_KEY_DIR=${key_dir}

# Testnet validator set override (allow < 4 validators)
QRDX_MIN_VALIDATORS=1

# RPC
QRDX_RPC_ENABLED=true
QRDX_RPC_HOST=127.0.0.1
QRDX_RPC_PORT=${rpc_port}
QRDX_WS_PORT=${ws_port}

# Logging
LOG_LEVEL=INFO
LOG_DIR=${LOGS_DIR}/node${node_id}

# Suppress liboqs version warnings
PYTHONWARNINGS=ignore

# Validator settings
EOF

    if [ "$is_validator" = true ]; then
        local wallet_path="${WALLETS_DIR}/validator_${validator_id}.json"
        cat >> "$config_file" << EOF
QRDX_VALIDATOR_ENABLED=true
QRDX_VALIDATOR_WALLET=${wallet_path}
QRDX_VALIDATOR_PASSWORD=testnet_validator_${validator_id}
EOF
    else
        cat >> "$config_file" << EOF
QRDX_VALIDATOR_ENABLED=false
EOF
    fi
    
    log_info "Created config for node ${node_id} (port ${node_port})"
}

# =============================================================================
# NODE MANAGEMENT
# =============================================================================

start_node() {
    local node_id=$1
    local config_file="${CONFIG_DIR}/node${node_id}.env"
    local pid_file="${TESTNET_DIR}/pids/node${node_id}.pid"
    local log_file="${LOGS_DIR}/node${node_id}/node.log"
    
    mkdir -p "$(dirname "$pid_file")"
    mkdir -p "$(dirname "$log_file")"
    
    # Source environment
    set -a
    source "$config_file"
    set +a
    
    # Start node with env vars and suppressed warnings
    cd "${PROJECT_DIR}"
    nohup python3 -W ignore run_node.py > "$log_file" 2>&1 &
    local pid=$!
    
    echo "$pid" > "$pid_file"
    
    log_info "Started node ${node_id} (PID: ${pid}, Port: ${QRDX_NODE_PORT})"
    
    # Wait for startup
    sleep 2
    
    # Check if still running
    if ! kill -0 "$pid" 2>/dev/null; then
        log_error "Node ${node_id} failed to start. Check logs: ${log_file}"
        tail -5 "$log_file" 2>/dev/null
        return 1
    fi
}

stop_node() {
    local node_id=$1
    local pid_file="${TESTNET_DIR}/pids/node${node_id}.pid"
    
    if [ ! -f "$pid_file" ]; then
        log_warn "Node ${node_id} PID file not found"
        return 0
    fi
    
    local pid=$(cat "$pid_file")
    
    if kill -0 "$pid" 2>/dev/null; then
        log_info "Stopping node ${node_id} (PID: ${pid})..."
        
        # Send SIGTERM for graceful shutdown
        kill -TERM "$pid" 2>/dev/null
        
        # Wait for graceful shutdown
        local timeout=10
        while kill -0 "$pid" 2>/dev/null && [ $timeout -gt 0 ]; do
            sleep 1
            timeout=$((timeout - 1))
        done
        
        # Send SIGINT if still running
        if kill -0 "$pid" 2>/dev/null; then
            log_warn "Sending SIGINT to node ${node_id}"
            kill -INT "$pid" 2>/dev/null
            sleep 2
        fi
        
        # Force kill as last resort
        if kill -0 "$pid" 2>/dev/null; then
            log_warn "Force killing node ${node_id}"
            kill -9 "$pid" 2>/dev/null
        fi
        
        rm -f "$pid_file"
        log_success "Node ${node_id} stopped"
    else
        log_warn "Node ${node_id} not running"
        rm -f "$pid_file"
    fi
}

# =============================================================================
# MAIN COMMANDS
# =============================================================================

cmd_start() {
    local num_nodes=$DEFAULT_NODES
    local num_validators=$DEFAULT_VALIDATORS
    
    # Parse arguments
    while [[ $# -gt 0 ]]; do
        case $1 in
            --nodes)
                num_nodes=$2
                shift 2
                ;;
            --validators)
                num_validators=$2
                shift 2
                ;;
            *)
                log_error "Unknown option: $1"
                return 1
                ;;
        esac
    done
    
    # Validation
    if [ "$num_validators" -gt "$num_nodes" ]; then
        log_error "Number of validators ($num_validators) cannot exceed number of nodes ($num_nodes)"
        return 1
    fi
    
    if [ "$num_validators" -lt 1 ]; then
        log_error "At least 1 validator required"
        return 1
    fi
    
    log_step "Starting QRDX Local Testnet"
    log_info "Nodes: ${num_nodes}"
    log_info "Validators: ${num_validators}"
    log_info "Bootstrap: node 0"
    echo
    
    # Check dependencies
    check_dependencies || return 1
    
    # Create directories
    mkdir -p "${TESTNET_DIR}" "${LOGS_DIR}" "${DATA_DIR}" "${WALLETS_DIR}" "${CONFIG_DIR}" "${TESTNET_DIR}/pids"
    
    # Generate master controller wallet
    log_step "Generating master controller wallet"
    local controller_address
    controller_address=$(generate_master_controller_wallet | tail -1)
    log_success "Master Controller: ${controller_address}"
    log_info "  Controls 10 system wallets (75M QRDX total)"
    log_info "  Wallet saved: ${WALLETS_DIR}/master_controller.json"
    echo
    
    # Generate validator wallets
    log_step "Generating validator wallets"
    for i in $(seq 0 $((num_validators - 1))); do
        generate_validator_wallet "$i" | tail -1 > /dev/null
        local wallet_path="${WALLETS_DIR}/validator_${i}.json"
        local address=$(get_wallet_address "$wallet_path")
        log_success "Validator ${i} wallet: ${address}"
    done
    
    # Create genesis
    create_genesis_config "$num_validators"
    
    # Setup databases
    setup_databases "$num_nodes"
    
    # Create node configurations
    log_step "Creating node configurations"
    for i in $(seq 0 $((num_nodes - 1))); do
        local is_bootstrap=false
        local is_validator=false
        local validator_id=""
        
        # Node 0 is bootstrap
        if [ "$i" -eq 0 ]; then
            is_bootstrap=true
        fi
        
        # First N nodes are validators
        if [ "$i" -lt "$num_validators" ]; then
            is_validator=true
            validator_id=$i
        fi
        
        create_node_config "$i" "$num_nodes" "$is_bootstrap" "$is_validator" "$validator_id"
    done
    
    # Start nodes (bootstrap first, then others with staggered delay)
    log_step "Starting nodes"
    for i in $(seq 0 $((num_nodes - 1))); do
        start_node "$i"
        if [ "$i" -eq 0 ]; then
            # Give bootstrap node extra time to fully initialize
            sleep 3
            # Verify bootstrap node is accepting connections
            if curl -s -o /dev/null -w '%{http_code}' "http://127.0.0.1:${DEFAULT_BASE_PORT}/get_nodes" 2>/dev/null | grep -q '200'; then
                log_success "Bootstrap node is accepting connections"
            else
                log_warn "Bootstrap node may still be initializing..."
                sleep 2
            fi
        else
            sleep 3  # Stagger non-bootstrap nodes
        fi
    done
    
    # Summary
    echo
    log_step "Testnet Started Successfully!"
    echo
    log_info "Network Details:"
    echo "  Chain ID:    9999"
    echo "  Network:     qrdx-testnet-local"
    echo "  Nodes:       ${num_nodes}"
    echo "  Validators:  ${num_validators}"
    echo
    log_info "Node Endpoints:"
    for i in $(seq 0 $((num_nodes - 1))); do
        local port=$((DEFAULT_BASE_PORT + i))
        local rpc=$((8545 + i))
        local role="Node"
        [ "$i" -eq 0 ] && role="Bootstrap"
        [ "$i" -lt "$num_validators" ] && role="${role} + Validator"
        echo "  Node ${i} (${role}): http://127.0.0.1:${port} (RPC: ${rpc})"
    done
    echo
    log_info "Master Controller Wallet:"
    local controller_wallet_path="${WALLETS_DIR}/master_controller.json"
    local controller_addr=$(get_wallet_address "$controller_wallet_path")
    echo "  Address:  ${controller_addr}"
    echo "  Purpose:  Controls all system wallets"
    echo "  Wallets:  10 system wallets (75M QRDX)"
    echo "  File:     ${controller_wallet_path}"
    echo
    log_info "Validator Wallets:"
    for i in $(seq 0 $((num_validators - 1))); do
        local wallet_path="${WALLETS_DIR}/validator_${i}.json"
        local address=$(get_wallet_address "$wallet_path")
        echo "  Validator ${i}: ${address}"
        echo "    Wallet: ${wallet_path}"
        echo "    Balance: ${DEFAULT_GENESIS_BALANCE} QRDX"
    done
    echo
    log_info "System Wallets (Controlled by Master):"
    echo "  Garbage Collector:    0x...0001 (0 QRDX, burner)"
    echo "  Community Grants:     0x...0002 (5M QRDX)"
    echo "  Developer Fund:       0x...0003 (10M QRDX)"
    echo "  Ecosystem Fund:       0x...0004 (8M QRDX)"
    echo "  Staking Rewards:      0x...0005 (15M QRDX)"
    echo "  Marketing:            0x...0006 (3M QRDX)"
    echo "  Liquidity Reserve:    0x...0007 (7M QRDX)"
    echo "  Treasury Multisig:    0x...0008 (20M QRDX)"
    echo "  Bug Bounty:           0x...0009 (1M QRDX)"
    echo "  Airdrop:              0x...000a (6M QRDX)"
    echo
    log_info "Useful Commands:"
    echo "  Status:  ./scripts/testnet.sh status"
    echo "  Logs:    ./scripts/testnet.sh logs [node_id]"
    echo "  Stop:    ./scripts/testnet.sh stop"
    echo
}

cmd_stop() {
    log_step "Stopping QRDX Local Testnet"
    
    if [ ! -d "${TESTNET_DIR}/pids" ]; then
        log_warn "No testnet running"
        return 0
    fi
    
    # Stop all nodes
    for pid_file in "${TESTNET_DIR}/pids"/node*.pid; do
        if [ -f "$pid_file" ]; then
            local node_id=$(basename "$pid_file" .pid | sed 's/node//')
            stop_node "$node_id"
        fi
    done
    
    log_success "Testnet stopped"
}

cmd_status() {
    log_step "QRDX Local Testnet Status"
    
    if [ ! -d "${TESTNET_DIR}/pids" ]; then
        log_warn "No testnet configured"
        return 0
    fi
    
    local running=0
    local stopped=0
    
    for pid_file in "${TESTNET_DIR}/pids"/node*.pid; do
        if [ -f "$pid_file" ]; then
            local node_id=$(basename "$pid_file" .pid | sed 's/node//')
            local pid=$(cat "$pid_file")
            local port=$((DEFAULT_BASE_PORT + node_id))
            
            local rpc=$((8545 + node_id))
            if kill -0 "$pid" 2>/dev/null; then
                local health=""
                if curl -s -o /dev/null -w '%{http_code}' "http://127.0.0.1:${port}/get_nodes" 2>/dev/null | grep -q '200'; then
                    health="${GREEN}[healthy]${NC}"
                else
                    health="${YELLOW}[starting]${NC}"
                fi
                echo -e "${GREEN}●${NC} Node ${node_id} - ${BOLD}RUNNING${NC} (PID: ${pid}, Port: ${port}, RPC: ${rpc}) ${health}"
                running=$((running + 1))
            else
                echo -e "${RED}●${NC} Node ${node_id} - ${BOLD}STOPPED${NC}"
                stopped=$((stopped + 1))
            fi
        fi
    done
    
    echo
    if [ $running -gt 0 ]; then
        log_info "Running: ${running} nodes"
    fi
    if [ $stopped -gt 0 ]; then
        log_warn "Stopped: ${stopped} nodes"
    fi
    if [ $running -eq 0 ] && [ $stopped -eq 0 ]; then
        log_info "No nodes found"
    fi
}

cmd_logs() {
    local node_id=${1:-0}
    local log_file="${LOGS_DIR}/node${node_id}/node.log"
    
    if [ ! -f "$log_file" ]; then
        log_error "Log file not found: ${log_file}"
        return 1
    fi
    
    log_info "Showing logs for node ${node_id}"
    log_info "Log file: ${log_file}"
    echo
    
    tail -f "$log_file"
}

cmd_clean() {
    log_step "Cleaning QRDX Local Testnet"
    
    # Stop nodes first
    cmd_stop
    
    # Remove testnet directory
    if [ -d "${TESTNET_DIR}" ]; then
        log_warn "Removing testnet directory: ${TESTNET_DIR}"
        read -p "Are you sure? (yes/no): " -r
        if [[ $REPLY == "yes" ]]; then
            rm -rf "${TESTNET_DIR}"
            log_success "Testnet directory removed"
            
            # Also clean up any stale node identity keys from shared location
            local shared_key="${PROJECT_DIR}/qrdx/node/node_key.pq"
            local shared_pub="${PROJECT_DIR}/qrdx/node/node_key.pq.pub"
            if [ -f "$shared_key" ] || [ -f "$shared_pub" ]; then
                log_info "Removing shared node identity keys..."
                rm -f "$shared_key" "$shared_pub"
                log_success "Shared node keys removed"
            fi
        else
            log_info "Cleanup cancelled"
        fi
    else
        log_info "No testnet directory found"
    fi
}

# =============================================================================
# MAIN
# =============================================================================

show_usage() {
    echo -e "${BOLD}QRDX Local Testnet Manager${NC}

${BOLD}USAGE:${NC}
    $0 <command> [options]

${BOLD}COMMANDS:${NC}
    start [--nodes N] [--validators V]
        Start local testnet with N nodes and V validators
        Default: ${DEFAULT_NODES} nodes, ${DEFAULT_VALIDATORS} validators

    stop
        Stop all running testnet nodes

    status
        Show status of all testnet nodes

    logs [node_id]
        Tail logs for specified node (default: node 0)

    clean
        Stop nodes and remove all testnet data

${BOLD}EXAMPLES:${NC}
    # Start with defaults (4 nodes, 2 validators)
    $0 start

    # Start with custom configuration
    $0 start --nodes 6 --validators 3

    # Check status
    $0 status

    # View logs
    $0 logs 0

    # Stop testnet
    $0 stop

${BOLD}CONFIGURATION:${NC}
    Testnet Directory: ${TESTNET_DIR}
    Base Port:         ${DEFAULT_BASE_PORT}
    Genesis Balance:   ${DEFAULT_GENESIS_BALANCE} QRDX per validator
"
}

main() {
    if [ $# -eq 0 ]; then
        show_usage
        exit 0
    fi
    
    local command=$1
    shift
    
    case $command in
        start)
            cmd_start "$@"
            ;;
        stop)
            cmd_stop "$@"
            ;;
        status)
            cmd_status "$@"
            ;;
        logs)
            cmd_logs "$@"
            ;;
        clean)
            cmd_clean "$@"
            ;;
        help|--help|-h)
            show_usage
            ;;
        *)
            log_error "Unknown command: $command"
            echo
            show_usage
            exit 1
            ;;
    esac
}

main "$@"
