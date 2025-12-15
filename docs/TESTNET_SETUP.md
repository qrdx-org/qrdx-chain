# QRDX Chain Testnet Setup Guide

## Quick Start

### Prerequisites
- Python 3.12+
- Git
- 4GB+ RAM
- Linux/macOS (tested on Debian)

### 1. Generate Validator Keypairs

First, generate the quantum-resistant keypairs for validators:

```bash
cd /workspaces/qrdx-chain

# Generate 3 validator keypairs (or adjust number as needed)
python3 << 'EOF'
import os
import pickle
from eth.crypto import generate_dilithium_keypair

# Create directory for keys
os.makedirs('/tmp/qrdx-validator-keys', exist_ok=True)

# Generate keypairs for each validator
num_validators = 3
for i in range(num_validators):
    # Generate random keypair (secure for testnet)
    private_key, public_key = generate_dilithium_keypair()
    
    # Save to disk
    key_file = f'/tmp/qrdx-validator-keys/validator-{i}.key'
    with open(key_file, 'wb') as f:
        pickle.dump((private_key.to_bytes(), public_key.to_bytes()), f)
    
    print(f"Generated validator {i}: {public_key.to_bytes()[:16].hex()}...")

print(f"\n✓ Generated {num_validators} validator keypairs in /tmp/qrdx-validator-keys/")
EOF
```

### 2. Start the Testnet

```bash
# Set number of validators (must match keypairs generated)
export QRDX_NUM_VALIDATORS=3

# Start 3-node testnet with log preservation
bash scripts/start_multi_node_testnet.sh 3 --keep
```

The script will:
- Generate genesis configuration
- Start 3 Trinity nodes
- Configure P2P networking
- Set up JSON-RPC endpoints
- Begin block production

### 3. Verify Testnet is Running

```bash
# Check Trinity processes
ps aux | grep trinity

# Should show 3 processes:
# - Node 0 (bootstrap)
# - Node 1
# - Node 2

# Test RPC endpoint
curl -X POST http://localhost:9422 \
  -H 'Content-Type: application/json' \
  -d '{"jsonrpc":"2.0","method":"eth_blockNumber","params":[],"id":1}'

# Should return current block number, e.g.:
# {"id":1,"jsonrpc":"2.0","result":"0x10"}
```

### 4. Monitor Testnet

```bash
# Watch Node 0 logs
tail -f /tmp/qrdx-node-0/trinity.log

# Check for successful block production
grep "successfully proposed block" /tmp/qrdx-node-0/trinity.log | tail -5

# Check signature validation
grep "signature.*validated successfully" /tmp/qrdx-node-0/trinity.log | wc -l

# Check for errors
grep -i "error\|exception" /tmp/qrdx-node-0/trinity.log | tail -10
```

## Node Configuration

### RPC Ports (default)
- Node 0: http://localhost:9422
- Node 1: http://localhost:9423
- Node 2: http://localhost:9424

### P2P Ports (default)
- Node 0: 30414 (bootstrap node)
- Node 1: 30415
- Node 2: 30416

### Data Directories
- Node 0: `/tmp/qrdx-node-0/`
- Node 1: `/tmp/qrdx-node-1/`
- Node 2: `/tmp/qrdx-node-2/`

### Log Files
- Node 0: `/tmp/qrdx-node-0/trinity.log`
- Node 1: `/tmp/qrdx-node-1/trinity.log`
- Node 2: `/tmp/qrdx-node-2/trinity.log`

## Testnet Parameters

- **Network ID**: 1337
- **Consensus**: QR-PoS (Quantum-Resistant Proof of Stake)
- **Slot Time**: 2 seconds
- **Signature Algorithm**: Dilithium ML-DSA-65 (3,309 bytes)
- **Validators**: 3 (configurable via QRDX_NUM_VALIDATORS)
- **Genesis Validators**: Active from epoch 0

## Common Operations

### Stop Testnet

```bash
# Graceful shutdown
pkill -TERM trinity

# Force shutdown if needed
pkill -9 trinity

# Clean up orphaned processes
pkill -9 python
```

### Clean Data and Restart

```bash
# Stop all nodes
pkill -9 trinity

# Remove old data
rm -rf /tmp/qrdx-node-*

# Regenerate keys (if needed)
# ... (see step 1)

# Restart
bash scripts/start_multi_node_testnet.sh 3 --keep
```

### Add More Validators

```bash
# Generate additional keypairs
python3 << 'EOF'
import pickle
from eth.crypto import generate_dilithium_keypair

# Add validator 3
private_key, public_key = generate_dilithium_keypair()
with open('/tmp/qrdx-validator-keys/validator-3.key', 'wb') as f:
    pickle.dump((private_key.to_bytes(), public_key.to_bytes()), f)
print(f"Generated validator 3: {public_key.to_bytes()[:16].hex()}...")
EOF

# Start testnet with 4 validators
export QRDX_NUM_VALIDATORS=4
bash scripts/start_multi_node_testnet.sh 4 --keep
```

## Testing RPC Methods

### Get Block Number
```bash
curl -X POST http://localhost:9422 \
  -H 'Content-Type: application/json' \
  -d '{"jsonrpc":"2.0","method":"eth_blockNumber","params":[],"id":1}'
```

### Get Block by Number
```bash
curl -X POST http://localhost:9422 \
  -H 'Content-Type: application/json' \
  -d '{"jsonrpc":"2.0","method":"eth_getBlockByNumber","params":["0x1", true],"id":1}'
```

### Get Chain ID
```bash
curl -X POST http://localhost:9422 \
  -H 'Content-Type: application/json' \
  -d '{"jsonrpc":"2.0","method":"eth_chainId","params":[],"id":1}'
```

### Using Python (web3.py)
```python
from web3 import Web3

# Connect to node
w3 = Web3(Web3.HTTPProvider('http://localhost:9422'))

# Check connection
print(f"Connected: {w3.is_connected()}")

# Get block number
print(f"Block: {w3.eth.block_number}")

# Get latest block
block = w3.eth.get_block('latest')
print(f"Latest block hash: {block['hash'].hex()}")
```

## Troubleshooting

### Nodes Won't Start

**Problem**: Port already in use
```
OSError: [Errno 98] error while attempting to bind on address ('127.0.0.1', 9422): address already in use
```

**Solution**: Kill orphaned processes
```bash
# Find processes holding ports
netstat -tulpn | grep -E "9422|9423|9424"

# Kill all Trinity processes
pkill -9 trinity
pkill -9 python

# Wait a few seconds
sleep 5

# Retry startup
bash scripts/start_multi_node_testnet.sh 3 --keep
```

### Signature Validation Failing

**Problem**: "Invalid Dilithium signature" warnings in logs

**Solution**: Ensure keypairs are loaded consistently
```bash
# Check keypairs exist
ls -la /tmp/qrdx-validator-keys/

# Should show:
# validator-0.key
# validator-1.key
# validator-2.key

# If missing, regenerate (see step 1)
```

### IPC Timeout Errors

**Problem**: "Timeout connecting to IPC socket"

**Solution**: Already fixed (timeout increased to 30s), but if issues persist:
```bash
# Check if DB manager is starting
grep "DBManager" /tmp/qrdx-node-0/trinity.log

# Increase timeout further if needed (edit trinity/_utils/connect.py)
```

### No Blocks Being Produced

**Problem**: Nodes running but no blocks

**Check**:
```bash
# Verify validator component is running
grep "QRPoSValidator" /tmp/qrdx-node-0/trinity.log

# Check for proposer selection
grep "proposer" /tmp/qrdx-node-0/trinity.log | tail -10

# Verify correct number of validators
grep "QRDX_NUM_VALIDATORS" /tmp/qrdx-node-0/trinity.log
```

## Performance Expectations

### Stable Testnet (3 nodes)
- **Block time**: ~6 seconds (with 3 validators, round-robin)
- **Blocks/minute**: ~10 blocks
- **Signature size**: 3,309 bytes per block
- **Uptime**: Tested stable for 3+ hours
- **Validation success rate**: 100%

### Resource Usage (per node)
- **Memory**: ~120 MB RSS
- **CPU**: <1% average, bursts to 5% during block production
- **Disk I/O**: Minimal (<1 MB/s)
- **Network**: Minimal (local testnet)

## Known Limitations

### 1. Keypair Storage (Testnet-Safe)
- Keys stored in `/tmp/qrdx-validator-keys/` as pickle files
- **Not secure for mainnet** - implement EIP-2335 encrypted keystore
- Acceptable for local testnet development

### 2. No Transaction Pool
- Testnet runs with `--disable-tx-pool`
- Empty blocks only (for consensus testing)
- Transaction support coming in Phase 4

### 3. Node Failure Recovery
- If 1 node fails, network continues (tested with 2/3 nodes)
- Manual restart needed (automatic restart not implemented)

## Next Steps

After verifying testnet works:

1. **Run Extended Test**: Let testnet run 24+ hours
2. **Monitor Metrics**: Check memory, CPU, block production
3. **Test RPC Coverage**: Validate all RPC methods
4. **Implement Secure Keystore**: EIP-2335 format for production

## Support

For issues or questions:
- Check logs: `/tmp/qrdx-node-*/trinity.log`
- Review completion report: `/docs/ai/sessions/2025-12-07_phase3-production-readiness/06_completion.md`
- See Phase 3 roadmap: `/docs/QR-PoS_Phase3_Roadmap.md`
