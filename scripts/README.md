# QRDX Chain Scripts

Collection of utility scripts for QRDX Chain development and testing.

## Local Testnet Scripts

### Start Local Testnet Node

Two options for starting a local QRDX testnet node:

#### Option 1: Bash Script
```bash
./scripts/start_local_testnet.sh [OPTIONS]
```

#### Option 2: Python Script  
```bash
python3 scripts/start_local_testnet.py [OPTIONS]
```

Both scripts provide the same functionality with these features:
- ✅ Fresh genesis state (150 validators)
- ✅ Temporary data directory (auto-cleanup on exit)
- ✅ QR-PoS consensus (2-second block time)
- ✅ Local RPC endpoint
- ✅ Validator mode

**Options:**
- `--port PORT` - P2P listening port (default: 30303)
- `--rpc-port PORT` - HTTP RPC port (default: 8545)
- `--network-id ID` - Network ID (default: 1337)
- `--validator-index N` - Run as validator N (0-149, default: 0)
- `--no-cleanup` - Don't delete data directory on exit
- `--verbose` - Enable debug logging (Python script only)
- `--help` - Show help message

**Examples:**
```bash
# Start with defaults
./scripts/start_local_testnet.sh

# Run as validator 5 with custom RPC port
python3 scripts/start_local_testnet.py --validator-index 5 --rpc-port 8555

# Keep data after stopping (for debugging)
./scripts/start_local_testnet.sh --no-cleanup

# Multiple validators on same machine
./scripts/start_local_testnet.sh --validator-index 0 --port 30303 --rpc-port 8545 &
./scripts/start_local_testnet.sh --validator-index 1 --port 30304 --rpc-port 8546 &
./scripts/start_local_testnet.sh --validator-index 2 --port 30305 --rpc-port 8547 &
```

**Test Connection:**
```bash
curl -X POST http://localhost:8545 \
  -H 'Content-Type: application/json' \
  -d '{"jsonrpc":"2.0","method":"eth_blockNumber","params":[],"id":1}'
```

**Stop Node:**
- Press `Ctrl+C` in the terminal running the script
- Data directory is automatically cleaned up (unless `--no-cleanup` was used)

## Test Scripts

### Smart Contract Tests

#### Governance System
```bash
python3 scripts/test_governance.py
```
Tests the on-chain governance system including proposals, voting, and timelocks.

#### Stake Tracker
```bash
python3 scripts/test_stake_tracker.py
```
Tests the QR-PoS stake tracking system for validators and delegation.

#### Router
```bash
python3 scripts/test_router.py
```
Tests the AMM router contract for swaps and liquidity operations.

#### QRDX AMM
```bash
python3 scripts/test_qrdx_amm.py
```
Tests the core AMM pool manager and concentrated liquidity features.

#### qRC20 Tokens
```bash
python3 scripts/test_qrc20.py
```
Tests the quantum-resistant token standard.

#### Bridge
```bash
python3 scripts/test_bridge.py
```
Tests the cross-chain asset bridge system.

### Run All Tests
```bash
# Run all contract tests
for test in scripts/test_*.py; do
    echo "Running $test..."
    python3 "$test"
done
```

## Development Scripts

### Deploy Bridge
```bash
python3 scripts/deploy_bridge.py
```
Deploys the bridge contracts to a running network.

### Mining
```bash
python3 scripts/mine_devnet.py
```
Utility for mining blocks on devnet (currently empty - to be implemented).

## Notes

- All scripts assume you're in the `/workspaces/qrdx-chain` directory
- Make sure to activate your Python virtual environment if using one
- The testnet scripts require Trinity/py-evm to be installed: `pip install -e .`
- Test scripts are standalone and don't require a running node

## Troubleshooting

### "Trinity not found"
```bash
cd /workspaces/qrdx-chain
pip install -e .
```

### "Port already in use"
Use different ports:
```bash
./scripts/start_local_testnet.sh --port 30304 --rpc-port 8555
```

### "Permission denied"
Make scripts executable:
```bash
chmod +x scripts/*.sh
chmod +x scripts/*.py
```

### Node won't start
Try with verbose logging:
```bash
python3 scripts/start_local_testnet.py --verbose
```

## Additional Resources

- [QRDX Whitepaper](../docs/QRDX-Whitepaper-v2.0.md)
- [Development Guide](../DEVELOPMENT.md)
- [AMM Documentation](../contracts/qrdx-amm/README.md)
