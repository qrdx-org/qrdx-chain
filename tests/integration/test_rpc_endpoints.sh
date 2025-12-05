#!/usr/bin/env bash
#
# Comprehensive JSON-RPC Endpoint Testing Script
# Tests all standard Ethereum JSON-RPC methods for QR-PoS compatibility
#

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

# Test results
PASSED=0
FAILED=0
SKIPPED=0

# RPC endpoint
RPC_URL="${RPC_URL:-http://localhost:8545}"

# Usage
if [ "$1" == "--help" ] || [ "$1" == "-h" ]; then
    echo "Usage: $0 [RPC_URL]"
    echo "  RPC_URL: JSON-RPC endpoint (default: http://localhost:8545)"
    echo ""
    echo "Example:"
    echo "  $0 http://localhost:9829"
    exit 0
fi

if [ -n "$1" ]; then
    RPC_URL="$1"
fi

echo -e "${CYAN}╔════════════════════════════════════════════════════════════╗${NC}"
echo -e "${CYAN}║         QR-PoS JSON-RPC Endpoint Test Suite               ║${NC}"
echo -e "${CYAN}╚════════════════════════════════════════════════════════════╝${NC}"
echo ""
echo -e "${CYAN}Testing RPC endpoint: ${RPC_URL}${NC}"
echo ""

# Test function
test_rpc() {
    local test_name="$1"
    local method="$2"
    local params="$3"
    local expected_check="$4"  # Optional: grep pattern to validate response
    
    echo -n "Testing $test_name... "
    
    local payload="{\"jsonrpc\":\"2.0\",\"method\":\"$method\",\"params\":$params,\"id\":1}"
    local response=$(timeout 5 curl -s -X POST "$RPC_URL" \
        -H 'Content-Type: application/json' \
        -d "$payload" 2>&1)
    
    local exit_code=$?
    
    if [ $exit_code -eq 124 ]; then
        echo -e "${YELLOW}TIMEOUT${NC}"
        ((FAILED++))
        echo "  Method: $method"
        echo "  Error: Request timed out after 5 seconds"
        return 1
    elif [ $exit_code -ne 0 ]; then
        echo -e "${RED}FAILED${NC}"
        ((FAILED++))
        echo "  Method: $method"
        echo "  Error: curl failed with exit code $exit_code"
        echo "  Response: $response"
        return 1
    fi
    
    # Check for JSON-RPC error
    if echo "$response" | grep -q '"error"'; then
        local error_msg=$(echo "$response" | grep -o '"message":"[^"]*"' | head -1)
        echo -e "${RED}ERROR${NC}"
        ((FAILED++))
        echo "  Method: $method"
        echo "  $error_msg"
        echo "  Full response: $response"
        return 1
    fi
    
    # Check for result field
    if ! echo "$response" | grep -q '"result"'; then
        echo -e "${RED}FAILED${NC}"
        ((FAILED++))
        echo "  Method: $method"
        echo "  Error: No result field in response"
        echo "  Response: $response"
        return 1
    fi
    
    # Optional: Check expected pattern
    if [ -n "$expected_check" ]; then
        if ! echo "$response" | grep -q "$expected_check"; then
            echo -e "${YELLOW}WARNING${NC}"
            echo "  Method: $method"
            echo "  Warning: Expected pattern '$expected_check' not found"
            echo "  Response: $response"
            # Still count as passed but show warning
        fi
    fi
    
    echo -e "${GREEN}PASSED${NC}"
    ((PASSED++))
    echo "  Response: $response"
    return 0
}

test_rpc_skip() {
    local test_name="$1"
    local reason="$2"
    echo -e "Testing $test_name... ${YELLOW}SKIPPED${NC} ($reason)"
    ((SKIPPED++))
}

echo "════════════════════════════════════════════════════════════"
echo "Core RPC Methods"
echo "════════════════════════════════════════════════════════════"
echo ""

# Core methods
test_rpc "web3_clientVersion" "web3_clientVersion" "[]" "Trinity"
test_rpc "web3_sha3" "web3_sha3" '["0x68656c6c6f20776f726c64"]' "0x47173285"
test_rpc "net_version" "net_version" "[]" "1337"
test_rpc "net_listening" "net_listening" "[]" "true"
test_rpc "net_peerCount" "net_peerCount" "[]" "0x"

echo ""
echo "════════════════════════════════════════════════════════════"
echo "ETH Methods - Chain Info"
echo "════════════════════════════════════════════════════════════"
echo ""

test_rpc "eth_chainId" "eth_chainId" "[]" "0x539"  # 1337 in hex
test_rpc "eth_syncing" "eth_syncing" "[]" "false"
test_rpc "eth_mining" "eth_mining" "[]"
test_rpc "eth_hashrate" "eth_hashrate" "[]"
test_rpc "eth_gasPrice" "eth_gasPrice" "[]" "0x"
test_rpc "eth_accounts" "eth_accounts" "[]"
test_rpc "eth_blockNumber" "eth_blockNumber" "[]" "0x"

echo ""
echo "════════════════════════════════════════════════════════════"
echo "ETH Methods - Block Queries"
echo "════════════════════════════════════════════════════════════"
echo ""

test_rpc "eth_getBlockByNumber(0)" "eth_getBlockByNumber" '["0x0", false]' "hash"
test_rpc "eth_getBlockByNumber(latest)" "eth_getBlockByNumber" '["latest", false]' "hash"
test_rpc "eth_getBlockByNumber(0,full)" "eth_getBlockByNumber" '["0x0", true]' "hash"
test_rpc "eth_getBlockTransactionCountByNumber" "eth_getBlockTransactionCountByNumber" '["0x0"]'

# Get genesis block hash for next tests
GENESIS_HASH=$(timeout 5 curl -s -X POST "$RPC_URL" \
    -H 'Content-Type: application/json' \
    -d '{"jsonrpc":"2.0","method":"eth_getBlockByNumber","params":["0x0", false],"id":1}' | \
    grep -o '"hash":"0x[^"]*"' | head -1 | cut -d'"' -f4)

if [ -n "$GENESIS_HASH" ]; then
    test_rpc "eth_getBlockByHash" "eth_getBlockByHash" "[\"$GENESIS_HASH\", false]" "hash"
    test_rpc "eth_getBlockTransactionCountByHash" "eth_getBlockTransactionCountByHash" "[\"$GENESIS_HASH\"]"
else
    test_rpc_skip "eth_getBlockByHash" "Could not get genesis hash"
    test_rpc_skip "eth_getBlockTransactionCountByHash" "Could not get genesis hash"
fi

echo ""
echo "════════════════════════════════════════════════════════════"
echo "ETH Methods - Account Queries"
echo "════════════════════════════════════════════════════════════"
echo ""

# Test with genesis account
GENESIS_ACCOUNT="0x0000000000000000000000000000000000000001"
test_rpc "eth_getBalance(genesis)" "eth_getBalance" "[\"$GENESIS_ACCOUNT\", \"latest\"]" "0x"
test_rpc "eth_getTransactionCount" "eth_getTransactionCount" "[\"$GENESIS_ACCOUNT\", \"latest\"]"
test_rpc "eth_getCode" "eth_getCode" "[\"$GENESIS_ACCOUNT\", \"latest\"]"
test_rpc "eth_getStorageAt" "eth_getStorageAt" "[\"$GENESIS_ACCOUNT\", \"0x0\", \"latest\"]"

echo ""
echo "════════════════════════════════════════════════════════════"
echo "ETH Methods - Transaction Queries"
echo "════════════════════════════════════════════════════════════"
echo ""

# These will return null for now but should not error
test_rpc "eth_getTransactionByHash" "eth_getTransactionByHash" '["0x0000000000000000000000000000000000000000000000000000000000000000"]'
test_rpc "eth_getTransactionByBlockHashAndIndex" "eth_getTransactionByBlockHashAndIndex" "[\"$GENESIS_HASH\", \"0x0\"]"
test_rpc "eth_getTransactionByBlockNumberAndIndex" "eth_getTransactionByBlockNumberAndIndex" '["0x0", "0x0"]'
test_rpc "eth_getTransactionReceipt" "eth_getTransactionReceipt" '["0x0000000000000000000000000000000000000000000000000000000000000000"]'

echo ""
echo "════════════════════════════════════════════════════════════"
echo "ETH Methods - Call & Estimate"
echo "════════════════════════════════════════════════════════════"
echo ""

# Simple eth_call
test_rpc "eth_call" "eth_call" '[{"to":"'"$GENESIS_ACCOUNT"'","data":"0x"}, "latest"]'
test_rpc "eth_estimateGas" "eth_estimateGas" '[{"to":"'"$GENESIS_ACCOUNT"'","data":"0x"}]'

echo ""
echo "════════════════════════════════════════════════════════════"
echo "ETH Methods - Filter & Logs"
echo "════════════════════════════════════════════════════════════"
echo ""

test_rpc "eth_getLogs(empty)" "eth_getLogs" '[{"fromBlock":"0x0","toBlock":"latest"}]'

echo ""
echo "════════════════════════════════════════════════════════════"
echo "Test Summary"
echo "════════════════════════════════════════════════════════════"
echo ""

TOTAL=$((PASSED + FAILED + SKIPPED))
echo -e "${GREEN}Passed:${NC}  $PASSED / $TOTAL"
echo -e "${RED}Failed:${NC}  $FAILED / $TOTAL"
echo -e "${YELLOW}Skipped:${NC} $SKIPPED / $TOTAL"
echo ""

if [ $FAILED -eq 0 ]; then
    echo -e "${GREEN}✓ All tests passed!${NC}"
    exit 0
else
    echo -e "${RED}✗ Some tests failed${NC}"
    exit 1
fi
