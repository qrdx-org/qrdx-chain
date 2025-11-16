# QR-PoS Testnet Setup Scripts

Complete toolkit for setting up and managing QR-PoS testnets with validators at genesis state.

## Quick Start

### Single Validator Setup (Development)

```bash
./scripts/quick_start.sh
cd quickstart && ./start-testnet.sh
```

### Multi-Validator Setup (Production-like)

```bash
python3 scripts/setup_testnet.py --validators 4 --output ./testnet
cd testnet && ./start-testnet.sh
```

## Scripts Overview

### 🚀 setup_testnet.py (Primary Tool)

**Purpose**: Create a complete QR-PoS testnet with genesis configuration

**Features**:
- Generate Dilithium validator keys (ML-DSA-87)
- Create genesis configuration with QR-PoS consensus
- Generate prefunded test accounts
- Docker Compose orchestration
- Automatic documentation generation

**Usage**:
```bash
# Basic setup
python3 scripts/setup_testnet.py \
    --validators 4 \
    --output ./testnet

# Advanced setup
python3 scripts/setup_testnet.py \
    --validators 8 \
    --chain-id 31337 \
    --output ./devnet \
    --initial-balance 1000000 \
    --prefunded 20
```

**Options**:
- `--validators N`: Number of validators (default: 4)
- `--chain-id ID`: Network chain ID (default: 1337)
- `--output DIR`: Output directory (default: ./testnet)
- `--initial-balance N`: ETH per test account (default: 1,000,000)
- `--prefunded N`: Number of test accounts (default: 10)

**Output**:
```
testnet/
├── genesis/genesis.json          # Genesis configuration
├── validators/validator_*.json   # Validator keystores
├── keys/                         # All keys backup
├── config/trinity.json           # Node config
├── docker-compose.yml            # Multi-node setup
├── start-testnet.sh             # Start script
├── stop-testnet.sh              # Stop script
├── reset-testnet.sh             # Reset script
└── README.md                    # Generated docs
```

---

### 🔑 validator_keys.py

**Purpose**: Manage validator keys (view, sign, verify, export)

**Commands**:

#### Show validator info
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

#### Sign a message
```bash
python3 scripts/validator_keys.py sign \
    --keystore validator_0.json \
    --message "Block proposal"
```

#### Verify signature
```bash
python3 scripts/validator_keys.py verify \
    --keystore validator_0.json \
    --message "Block proposal" \
    --signature <hex_signature>
```

#### Generate new key
```bash
python3 scripts/validator_keys.py generate \
    --output new_validator.json
```

#### Export keys
```bash
# JSON format
python3 scripts/validator_keys.py export \
    --keystore validator_0.json \
    --format json

# Hex format
python3 scripts/validator_keys.py export \
    --keystore validator_0.json \
    --format hex

# Raw binary files
python3 scripts/validator_keys.py export \
    --keystore validator_0.json \
    --format raw \
    --output ./exported/
```

---

### 📊 check_testnet.py

**Purpose**: Monitor testnet status and health

**Usage**:

#### Single check
```bash
python3 scripts/check_testnet.py --rpc http://localhost:8545
```

Output:
```
================================================================================
QR-PoS TESTNET STATUS
================================================================================

🔌 Connection
  RPC: http://localhost:8545
  ✓ Connected

⛓️  Chain Information
  Chain ID: 1337
  Network ID: 1337
  Block Number: 1,234
  Peers: 3
  Gas Price: 1,000,000,000 wei

📦 Latest Block
  Number: 1,234
  Hash: 0x1234...5678
  Timestamp: 2025-11-14 10:30:45
  Age: 2 seconds ago
  Transactions: 0
  Gas Used: 0 / 30,000,000 (0.0%)
```

#### Watch mode (continuous monitoring)
```bash
python3 scripts/check_testnet.py --rpc http://localhost:8545 --watch --interval 5
```

---

### ⚡ quick_start.sh

**Purpose**: Rapid single-validator testnet setup

**Usage**:
```bash
./scripts/quick_start.sh
```

**What it does**:
1. Creates single-validator testnet at `./quickstart/`
2. Generates 3 prefunded test accounts
3. Provides instructions to start

**Use case**: Quick development testing, demo purposes

---

## Complete Workflow Example

### 1. Setup Testnet

```bash
# Create 4-validator testnet
python3 scripts/setup_testnet.py \
    --validators 4 \
    --chain-id 1337 \
    --output ./my-testnet

cd my-testnet
```

### 2. Review Configuration

```bash
# Check genesis config
cat genesis/genesis.json

# Review validators
ls -la validators/

# Check test accounts
cat keys/test_accounts.json
```

### 3. Start Network

```bash
./start-testnet.sh
```

### 4. Monitor Status

```bash
# In another terminal
python3 ../scripts/check_testnet.py --rpc http://localhost:8545 --watch
```

### 5. Check Validator Info

```bash
python3 ../scripts/validator_keys.py info \
    --keystore validators/validator_0.json
```

### 6. Sign Test Message

```bash
python3 ../scripts/validator_keys.py sign \
    --keystore validators/validator_0.json \
    --message "Hello QR-PoS"
```

### 7. Use Test Account

```python
import json
from trinity.crypto.pq.dilithium import DilithiumPrivateKey

# Load test account
with open('keys/test_account_0.json') as f:
    account = json.load(f)

# Load private key
privkey = DilithiumPrivateKey.from_bytes(
    bytes.fromhex(account['crypto']['ciphertext']),
    bytes.fromhex(account['public_key'])
)

# Sign transaction
tx_data = b"transaction data"
signature = privkey.sign(tx_data)
print(f"Signed: {signature.hex()[:32]}...")
```

### 8. Stop When Done

```bash
./stop-testnet.sh
```

### 9. Reset (Optional)

```bash
# Delete all blockchain data
./reset-testnet.sh

# Start fresh
./start-testnet.sh
```

---

## Key Features

### 🔐 Quantum-Resistant Cryptography
- **Algorithm**: ML-DSA-87 Dilithium (NIST PQC standard)
- **Public Key**: 2,592 bytes
- **Signature**: 4,627 bytes
- **Address**: 32 bytes (BLAKE3 hash)

### ⛓️ QR-PoS Consensus
- **Slot Duration**: 2 seconds
- **Epoch**: 32 slots (64 seconds)
- **Finality**: Casper FFG (2/3 supermajority)
- **Fork Choice**: LMD-GHOST

### 🏗️ Genesis Configuration
- Pre-configured validator set
- Prefunded test accounts
- Custom chain ID
- EIP-1559 compatible

### 🐳 Docker Support
- Multi-validator orchestration
- Independent containers per validator
- Persistent data volumes
- Easy networking

---

## Validator Requirements

### Minimum Stake
- **32,000 QRDX** per validator
- Automatically allocated in genesis

### Hardware Requirements
- **CPU**: 2+ cores
- **RAM**: 4+ GB
- **Storage**: 50+ GB SSD
- **Network**: 10+ Mbps

### Key Management
- Dilithium keys stored in JSON keystores
- Unencrypted (development only - **DO NOT use in production**)
- Backup recommended

---

## Network Endpoints

Each validator exposes:
- **RPC**: `http://localhost:8545+N`
- **WebSocket**: `ws://localhost:8546+N`
- **P2P**: Port `30303+N`

Examples:
- Validator 0: RPC at `http://localhost:8545`
- Validator 1: RPC at `http://localhost:8546`
- Validator 2: RPC at `http://localhost:8547`

---

## Troubleshooting

### Cannot connect to RPC
```bash
# Check if container is running
docker-compose ps

# Check logs
docker-compose logs validator-0

# Verify port binding
docker-compose port validator-0 8545
```

### Validators not proposing
```bash
# Check validator is in genesis
jq '.config.qrpos.validators' genesis/genesis.json

# Check logs for errors
docker-compose logs | grep -i error

# Verify keystore mounted
docker-compose exec validator-0 ls -la /validator.json
```

### Finality stuck
```bash
# Check how many validators online
docker-compose ps | grep -c validator

# Need at least 2/3 validators for finality
# With 4 validators: need 3 online

# Check attestations
docker-compose logs | grep -i attestation
```

### Reset everything
```bash
./reset-testnet.sh
# Deletes all blockchain data
# Keeps keys and configuration
```

---

## Security Notes

⚠️ **WARNING**: These scripts are for **TESTING ONLY**

**Do NOT use for production** because:
1. Keystores are unencrypted
2. Private keys stored in plaintext
3. No slashing protection
4. Default genesis state (not secure)
5. RPC endpoints have no authentication

For production:
- Encrypt all keystores
- Use hardware security modules (HSM)
- Implement slashing protection
- Secure RPC with authentication
- Use proper genesis configuration
- Enable firewall rules
- Set up monitoring and alerts

---

## Documentation

- **Complete Guide**: [TESTNET_SETUP_GUIDE.md](../TESTNET_SETUP_GUIDE.md)
- **Implementation Status**: [PQ_IMPLEMENTATION_STATUS.md](../PQ_IMPLEMENTATION_STATUS.md)
- **Whitepaper**: [whitepaper.txt](../whitepaper.txt)

---

## Support

- **GitHub**: https://github.com/qrdx-org/qrdx-chain
- **Issues**: https://github.com/qrdx-org/qrdx-chain/issues
- **Docs**: https://docs.qrdx.org

---

**Last Updated**: November 2025  
**Version**: 1.0.0  
**Status**: ✅ Ready for Testing
