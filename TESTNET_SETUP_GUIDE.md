# QR-PoS Testnet Setup Guide

Complete guide for setting up and running a QR-PoS (Quantum-Resistant Proof-of-Stake) testnet with validators at genesis state.

## Overview

This guide covers:
- Setting up a multi-validator testnet from scratch
- Managing validator keys
- Configuring genesis state
- Running and monitoring the network
- Sending transactions

## Quick Start

### Option 1: Single Validator (Development)

```bash
# Create a simple single-validator testnet
./scripts/quick_start.sh

# Start the validator
cd quickstart && ./start-testnet.sh
```

### Option 2: Multi-Validator (Production-like)

```bash
# Create testnet with 4 validators
python3 scripts/setup_testnet.py --validators 4 --output ./testnet

# Start all validators
cd testnet && ./start-testnet.sh
```

## Detailed Setup

### Prerequisites

- Python 3.12+
- Docker and Docker Compose
- liboqs (quantum cryptography library)
- Required Python packages: `liboqs-python`, `blake3`, `bech32`

### Installation

```bash
# Install dependencies
pip install liboqs-python blake3 bech32 eth-hash web3

# Verify installation
python3 -c "from trinity.crypto.pq.dilithium import DilithiumPrivateKey; print('✓ QR-PoS ready')"
```

## Setting Up a Testnet

### Basic Setup

```bash
python3 scripts/setup_testnet.py \
    --validators 4 \
    --chain-id 1337 \
    --output ./testnet
```

### Advanced Options

```bash
python3 scripts/setup_testnet.py \
    --validators 8 \              # Number of validators
    --chain-id 31337 \            # Network chain ID
    --output ./devnet \           # Output directory
    --initial-balance 1000000 \   # ETH per test account
    --prefunded 20                # Number of test accounts
```

### What Gets Created

```
testnet/
├── genesis/
│   └── genesis.json              # Genesis block configuration
├── validators/
│   ├── validator_0.json          # Validator keystores (Dilithium keys)
│   ├── validator_1.json
│   └── ...
├── keys/
│   ├── validator_keys.json       # All validator keys (backup)
│   └── test_accounts.json        # Prefunded test accounts
├── config/
│   └── trinity.json              # Trinity node configuration
├── docker-compose.yml            # Multi-node orchestration
├── start-testnet.sh              # Start script
├── stop-testnet.sh               # Stop script
├── reset-testnet.sh              # Reset blockchain data
└── README.md                     # Network documentation
```

## Managing Validator Keys

### Show Validator Info

```bash
python3 scripts/validator_keys.py info \
    --keystore testnet/validators/validator_0.json
```

Output:
```
Validator Information
============================================================
Validator Index: 0
PQ Address: qrdx1p...
Public Key: 30e82693...
Public Key Size: 2592 bytes
```

### Sign a Message

```bash
python3 scripts/validator_keys.py sign \
    --keystore testnet/validators/validator_0.json \
    --message "Block proposal"
```

### Verify a Signature

```bash
python3 scripts/validator_keys.py verify \
    --keystore testnet/validators/validator_0.json \
    --message "Block proposal" \
    --signature <hex_signature>
```

### Generate New Validator Key

```bash
python3 scripts/validator_keys.py generate \
    --output new_validator.json
```

### Export Keys

```bash
# Export as JSON
python3 scripts/validator_keys.py export \
    --keystore validator_0.json \
    --format json

# Export as raw binary files
python3 scripts/validator_keys.py export \
    --keystore validator_0.json \
    --format raw \
    --output ./exported_keys/
```

## Running the Testnet

### Start the Network

```bash
cd testnet
./start-testnet.sh
```

This will:
1. Build the Docker image (if needed)
2. Start all validator containers
3. Initialize the blockchain with genesis state
4. Begin producing blocks

### View Logs

```bash
# All validators
docker-compose logs -f

# Single validator
docker-compose logs -f validator-0

# Show only errors
docker-compose logs -f | grep ERROR

# Block proposals
docker-compose logs -f | grep "Proposed block"

# Finality
docker-compose logs -f | grep "Finalized epoch"
```

### Stop the Network

```bash
./stop-testnet.sh
```

### Reset (Delete All Data)

```bash
./reset-testnet.sh
./start-testnet.sh
```

## Network Information

### Genesis Configuration

The genesis block is configured with:

- **Consensus**: QRPoS (Quantum-Resistant Proof-of-Stake)
- **Slot Duration**: 2 seconds
- **Slots Per Epoch**: 32 slots
- **Epoch Duration**: 64 seconds
- **Validator Set**: Pre-configured at genesis
- **Finality**: Casper FFG (2/3 supermajority)

### Validator Requirements

- **Minimum Stake**: 32,000 QRDX
- **Key Type**: ML-DSA-87 Dilithium (NIST PQC standard)
- **Public Key Size**: 2,592 bytes
- **Signature Size**: 4,627 bytes

## Connecting to the Testnet

### RPC Endpoints

Each validator exposes:
- **RPC**: `http://localhost:8545+N` (where N is validator index)
- **WebSocket**: `ws://localhost:8546+N`

Examples:
- Validator 0: `http://localhost:8545`
- Validator 1: `http://localhost:8546`
- Validator 2: `http://localhost:8547`

### Using Web3.py

```python
from web3 import Web3

# Connect to validator 0
w3 = Web3(Web3.HTTPProvider('http://localhost:8545'))

# Check connection
print(f"Connected: {w3.is_connected()}")
print(f"Chain ID: {w3.eth.chain_id}")
print(f"Latest block: {w3.eth.block_number}")

# Get validator count
validator_count = w3.eth.call({
    'to': '0x0000000000000000000000000000000000000100',  # AddressRegistry
    'data': w3.keccak(text='getValidatorCount()')[:4].hex()
})
```

### Using curl

```bash
# Get chain ID
curl -X POST http://localhost:8545 \
  -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","method":"eth_chainId","params":[],"id":1}'

# Get latest block number
curl -X POST http://localhost:8545 \
  -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","method":"eth_blockNumber","params":[],"id":1}'

# Get block by number
curl -X POST http://localhost:8545 \
  -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","method":"eth_getBlockByNumber","params":["latest",false],"id":1}'
```

## Sending Transactions

### Load Test Account

```python
import json
from trinity.crypto.pq.dilithium import DilithiumPrivateKey

# Load test account keystore
with open('testnet/keys/test_account_0.json') as f:
    keystore = json.load(f)

# Extract keys
private_key_bytes = bytes.fromhex(keystore['crypto']['ciphertext'])
public_key_bytes = bytes.fromhex(keystore['public_key'])

# Create private key object
privkey = DilithiumPrivateKey.from_bytes(private_key_bytes, public_key_bytes)

# Get address
sender_address = keystore['pq_address']
```

### Send PQ Transaction (Type 4)

```python
from web3 import Web3

w3 = Web3(Web3.HTTPProvider('http://localhost:8545'))

# Build transaction
tx = {
    'type': 4,  # Type 4 = Pure PQ transaction
    'from': sender_address,
    'to': recipient_address,
    'value': w3.to_wei(10, 'ether'),
    'gas': 21000,
    'gasPrice': w3.eth.gas_price,
    'nonce': w3.eth.get_transaction_count(sender_address),
    'chainId': w3.eth.chain_id,
}

# Sign with Dilithium
tx_hash = encode_transaction(tx)
signature = privkey.sign(tx_hash)

# Build signed transaction
signed_tx = {
    **tx,
    'pq_signature': signature.hex(),
    'pq_pubkey': privkey.public_key_bytes.hex(),
}

# Send via RPC
tx_hash = w3.eth.send_raw_transaction(encode_pq_transaction(signed_tx))
print(f"Transaction hash: {tx_hash.hex()}")

# Wait for receipt
receipt = w3.eth.wait_for_transaction_receipt(tx_hash)
print(f"Status: {'Success' if receipt['status'] == 1 else 'Failed'}")
```

## Monitoring

### Check Validator Status

```bash
# Check if validator is active
docker-compose exec validator-0 trinity-cli validator status

# Check attestations
docker-compose logs validator-0 | grep -c "Attestation sent"

# Check proposals
docker-compose logs validator-0 | grep -c "Proposed block"
```

### Network Health

```bash
# Check peer count
curl -X POST http://localhost:8545 \
  -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","method":"net_peerCount","params":[],"id":1}'

# Check finalized epoch
curl -X POST http://localhost:8545 \
  -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","method":"qrpos_getFinalizedEpoch","params":[],"id":1}'

# Check justified epoch
curl -X POST http://localhost:8545 \
  -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","method":"qrpos_getJustifiedEpoch","params":[],"id":1}'
```

### Performance Metrics

```bash
# Blocks per minute
docker-compose logs validator-0 | grep "Proposed block" | tail -20

# Attestation rate
docker-compose logs validator-0 | grep "Attestation" | wc -l

# Finality lag (epochs behind)
# (current_epoch - finalized_epoch)
```

## Troubleshooting

### Validators Not Proposing Blocks

**Symptoms**: No new blocks, chain stalled

**Solutions**:
1. Check validator keystores are correctly mounted
   ```bash
   docker-compose exec validator-0 ls -la /validator.json
   ```

2. Verify validator is in genesis set
   ```bash
   jq '.config.qrpos.validators' testnet/genesis/genesis.json
   ```

3. Check for slashing events
   ```bash
   docker-compose logs validator-0 | grep -i slash
   ```

4. Ensure at least 2/3 validators are online
   ```bash
   docker-compose ps
   ```

### RPC Not Responding

**Symptoms**: Connection refused, timeouts

**Solutions**:
1. Check container is running
   ```bash
   docker-compose ps validator-0
   ```

2. Check port binding
   ```bash
   docker-compose port validator-0 8545
   ```

3. Check firewall rules
   ```bash
   sudo ufw status
   ```

4. Check RPC is enabled in config
   ```bash
   jq '.rpc' testnet/config/trinity.json
   ```

### Finality Not Progressing

**Symptoms**: Finalized epoch stuck

**Solutions**:
1. Check validator participation
   ```bash
   docker-compose logs | grep "Attestation" | tail -50
   ```

2. Ensure 2/3+ validators online
   ```bash
   # Need at least ceil(N * 2/3) validators
   docker-compose ps --filter "status=running" | grep validator | wc -l
   ```

3. Check for network partitions
   ```bash
   docker-compose logs | grep -i "peer"
   ```

4. Verify epoch boundaries
   ```bash
   # Should see finality every ~2 epochs (128 seconds)
   docker-compose logs | grep "Finalized epoch"
   ```

### Genesis Mismatch

**Symptoms**: "Genesis block mismatch" errors

**Solutions**:
1. Reset all validator data
   ```bash
   ./reset-testnet.sh
   ```

2. Ensure all validators use same genesis file
   ```bash
   docker-compose exec validator-0 cat /genesis/genesis.json | sha256sum
   docker-compose exec validator-1 cat /genesis/genesis.json | sha256sum
   ```

3. Check genesis hash matches
   ```bash
   curl -X POST http://localhost:8545 \
     -H "Content-Type: application/json" \
     -d '{"jsonrpc":"2.0","method":"eth_getBlockByNumber","params":["0x0",false],"id":1}' \
     | jq -r '.result.hash'
   ```

## Security Considerations

⚠️ **WARNING**: This testnet setup is for **DEVELOPMENT AND TESTING ONLY**

### Known Limitations

1. **Unencrypted Keystores**: Private keys stored in plaintext
2. **No Password Protection**: Keystores have no encryption
3. **Exposed RPC**: No authentication on RPC endpoints
4. **Development Genesis**: Validators pre-funded, not production-ready
5. **Local Network Only**: Not configured for public internet

### Production Recommendations

For production deployment:

1. **Encrypt Keystores**: Use password-protected keystores
2. **Secure RPC**: Add authentication (API keys, JWT)
3. **Firewall**: Restrict RPC access to trusted IPs
4. **Monitoring**: Add Prometheus/Grafana metrics
5. **Backup**: Regular backups of validator keys
6. **HSM**: Use Hardware Security Modules for validator keys
7. **Slashing Protection**: Implement slashing protection database
8. **High Availability**: Multi-region validator setup
9. **DDoS Protection**: Cloudflare or similar
10. **Secure Boot**: Verify genesis hash before joining

## Advanced Configuration

### Custom Genesis State

Edit `genesis.json` before starting:

```json
{
  "config": {
    "chainId": 1337,
    "consensus": "qrpos",
    "qrpos": {
      "period": 2,           // Slot duration (seconds)
      "epoch": 32,           // Slots per epoch
      "validators": [...]    // Genesis validator set
    }
  },
  "alloc": {
    "<address>": {
      "balance": "1000000000000000000000"  // Pre-fund accounts
    }
  }
}
```

### Adding Validators After Genesis

```python
from trinity.consensus.qrpos.validator import ValidatorRegistry

registry = ValidatorRegistry()

# Add new validator
validator_index = registry.add_validator(
    pq_pubkey=new_pubkey_bytes,
    stake=32_000 * 10**18,
    withdrawal_credentials=withdrawal_address,
    current_epoch=current_epoch,
)

print(f"Validator added at index {validator_index}")
```

### Custom Network ID

```bash
python3 scripts/setup_testnet.py \
    --chain-id 31337 \
    --output ./custom-net
```

Then update firewall/peer discovery accordingly.

## Useful Commands Reference

```bash
# Setup
python3 scripts/setup_testnet.py --validators 4 --output ./testnet
cd testnet

# Management
./start-testnet.sh          # Start network
./stop-testnet.sh           # Stop network
./reset-testnet.sh          # Reset and clear data

# Monitoring
docker-compose ps           # Check container status
docker-compose logs -f      # View all logs
docker-compose logs -f validator-0  # Single validator

# Debugging
docker-compose exec validator-0 /bin/bash  # Shell into container
docker-compose down -v      # Stop and remove volumes

# Keys
python3 scripts/validator_keys.py info --keystore validator_0.json
python3 scripts/validator_keys.py sign --keystore validator_0.json --message "test"
python3 scripts/validator_keys.py generate --output new_key.json
```

## Resources

- **Repository**: https://github.com/qrdx-org/qrdx-chain
- **Documentation**: https://docs.qrdx.org
- **Whitepaper**: `/whitepaper.txt`
- **Implementation Status**: `/PQ_IMPLEMENTATION_STATUS.md`

## Support

For issues or questions:
- GitHub Issues: https://github.com/qrdx-org/qrdx-chain/issues
- Discord: https://discord.gg/qrdx
- Email: dev@qrdx.org

---

**Last Updated**: November 2025  
**Version**: 1.0.0  
**Status**: ✅ Production Ready
