# QRDX Chain Docker Containers

## Production-Ready Architecture

QRDX Chain provides two separate Docker containers optimized for different roles:

### 🔹 **qrdx-node** - Full Node
Runs a full node that participates in the network but does NOT validate blocks or earn rewards.

### 🔸 **qrdx-validator** - Validator Node  
Runs a validator node that actively participates in QR-PoS consensus, proposes blocks, and earns rewards.

---

## Container Specifications

### Common Features (Both Containers)
- **Base**: Python 3.12 on Debian Bullseye
- **Quantum Security**: CRYSTALS-Dilithium (ML-DSA-65) signatures via liboqs 0.15.0
- **Size**: ~1.23GB
- **Network**: QRDX Chain mainnet/testnet compatible
- **Ports**: 
  - 30303 (P2P networking)
  - 8545 (HTTP RPC)
  - 8546 (WebSocket RPC)

### Consensus Parameters (Per Whitepaper v2.0)
- **Validators**: 150 maximum
- **Min Stake**: 100,000 QRDX per validator
- **Block Time**: 2 seconds
- **Finality**: Single-slot (sub-second BFT finality)
- **Slashing**: 5% penalty for misbehavior
- **Target TPS**: 5,000+

---

## 🔹 QRDX Node (Full Node)

### Purpose
- Sync blockchain state
- Serve RPC requests
- Relay transactions and blocks
- Support dApp integrations

### Build
```bash
docker build -f docker/Dockerfile.node -t qrdx-node:latest .
```

### Run
```bash
# Basic full node
docker run -d \
  --name qrdx-node \
  -p 30303:30303 \
  -p 8545:8545 \
  -p 8546:8546 \
  -v qrdx-node-data:/root/.local/share/trinity \
  qrdx-node:latest

# With custom network ID
docker run -d \
  --name qrdx-node-testnet \
  -p 30303:30303 \
  -p 8545:8545 \
  -v qrdx-testnet-data:/root/.local/share/trinity \
  qrdx-node:latest \
  --network-id 5678 \
  --enable-http-apis eth,net,web3
```

### Configuration
No special configuration required. Node will sync from network.

---

## 🔸 QRDX Validator (Validator Node)

### Purpose
- Participate in QR-PoS consensus
- Propose and sign blocks
- Earn staking rewards
- Require **100,000 QRDX minimum stake**

### Prerequisites

#### 1. Generate Validator Keys
You MUST have a Dilithium (ML-DSA-65) keypair:
```bash
# Generate Dilithium keypair (example using Python)
from eth.crypto import DilithiumPrivateKey

privkey = DilithiumPrivateKey.random()
pubkey = privkey.public_key

# Save keys securely
with open('validator_private_key.pem', 'wb') as f:
    f.write(privkey.to_bytes())
    
with open('validator_public_key.pem', 'wb') as f:
    f.write(pubkey.to_bytes())
```

#### 2. Stake 100,000 QRDX
Register as validator on-chain via StakeTracker contract:
```solidity
// Call StakeTracker.registerValidator()
// Requires 100,000 QRDX (100_000 * 10^18 wei)
function registerValidator(
    bytes calldata dilithiumPublicKey,  // 1,952 bytes
    uint256 commissionRate              // 0-2000 (0-20%)
) external payable returns (uint256 validatorIndex);
```

### Build
```bash
docker build -f docker/Dockerfile.validator -t qrdx-validator:latest .
```

### Run
```bash
# CRITICAL: Mount your validator keys directory
docker run -d \
  --name qrdx-validator \
  -p 30303:30303 \
  -p 8545:8545 \
  -p 8546:8546 \
  -v /path/to/your/validator_keys:/root/.local/share/trinity/validator_keys \
  -v qrdx-validator-data:/root/.local/share/trinity \
  qrdx-validator:latest

# With environment variables
docker run -d \
  --name qrdx-validator-prod \
  -p 30303:30303 \
  -v /secure/validator_keys:/root/.local/share/trinity/validator_keys \
  -v qrdx-validator-data:/root/.local/share/trinity \
  -e NETWORK_ID=1234 \
  qrdx-validator:latest
```

### Validator Keys Directory Structure
```
validator_keys/
├── validator_private_key.pem    # Dilithium private key (KEEP SECRET!)
├── validator_public_key.pem     # Dilithium public key (1,952 bytes)
└── validator_config.json        # Optional: validator metadata
```

### Security Best Practices

⚠️ **CRITICAL SECURITY REQUIREMENTS**:

1. **Never expose private keys**: Use encrypted volumes, HSM, or secure key management
2. **Backup keys securely**: Loss of validator keys = loss of staked QRDX
3. **Monitor uptime**: Missing >10% attestations = 5% slashing penalty
4. **Single instance**: Running same validator on multiple nodes = double-signing = 50% slashing
5. **Network security**: Use firewall rules, VPN, or private networks for validator communication

### Slashing Conditions (Per Whitepaper)
| Violation | Penalty | Description |
|-----------|---------|-------------|
| Double-signing | 50% stake | Proposing two blocks at same slot |
| Invalid attestation | 30% stake | Attesting to provably invalid block |
| Downtime | 5% stake | Missing >10% attestations in epoch |
| Bridge fraud | 100% stake | Submitting false bridge proofs |

### Monitoring
```bash
# Check validator logs
docker logs -f qrdx-validator

# Check validator status
docker exec qrdx-validator trinity --version

# Health check
curl http://localhost:8545 -X POST \
  -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","method":"eth_blockNumber","params":[],"id":1}'
```

---

## Comparison Matrix

| Feature | qrdx-node | qrdx-validator |
|---------|-----------|----------------|
| **Syncs blockchain** | ✅ Yes | ✅ Yes |
| **RPC server** | ✅ Yes | ✅ Yes |
| **P2P networking** | ✅ Yes | ✅ Yes |
| **Proposes blocks** | ❌ No | ✅ Yes |
| **Signs attestations** | ❌ No | ✅ Yes |
| **Earns rewards** | ❌ No | ✅ Yes |
| **Min stake required** | 0 QRDX | 100,000 QRDX |
| **Validator keys** | Not needed | **Required** |
| **Slashing risk** | None | Yes (if misbehave) |
| **Hardware requirements** | Moderate | High |
| **Network bandwidth** | Moderate | High |

---

## Hardware Requirements

### QRDX Node (Full Node)
- **CPU**: 4+ cores
- **RAM**: 8 GB
- **Storage**: 500 GB SSD (growing)
- **Network**: 10 Mbps stable connection

### QRDX Validator
- **CPU**: 8+ cores (for signature computation)
- **RAM**: 16 GB
- **Storage**: 1 TB NVMe SSD
- **Network**: 100 Mbps stable, low latency (<50ms to peers)
- **Uptime**: 99%+ required (to avoid slashing)

---

## Docker Compose Examples

### Full Node Setup
```yaml
# docker-compose.yml
version: '3.8'

services:
  qrdx-node:
    image: qrdx-node:latest
    container_name: qrdx-fullnode
    ports:
      - "30303:30303"
      - "8545:8545"
      - "8546:8546"
    volumes:
      - qrdx-node-data:/root/.local/share/trinity
    restart: unless-stopped
    command:
      - --network-id=1234
      - --enable-http-apis=eth,net,web3
      - --http-listen-address=0.0.0.0

volumes:
  qrdx-node-data:
```

### Validator Setup
```yaml
# docker-compose.validator.yml
version: '3.8'

services:
  qrdx-validator:
    image: qrdx-validator:latest
    container_name: qrdx-validator
    ports:
      - "30303:30303"
      - "127.0.0.1:8545:8545"  # Only localhost for security
      - "127.0.0.1:8546:8546"
    volumes:
      - /secure/path/validator_keys:/root/.local/share/trinity/validator_keys:ro
      - qrdx-validator-data:/root/.local/share/trinity
    environment:
      - NETWORK_ID=1234
    restart: unless-stopped
    healthcheck:
      test: ["CMD", "curl", "-f", "http://localhost:8545"]
      interval: 30s
      timeout: 10s
      retries: 3
    logging:
      driver: json-file
      options:
        max-size: "100m"
        max-file: "10"

volumes:
  qrdx-validator-data:
```

---

## Production Deployment Checklist

### For All Nodes
- [ ] Persistent storage volumes configured
- [ ] Firewall rules in place (allow 30303, restrict 8545/8546)
- [ ] Monitoring and logging configured
- [ ] Automatic restart policy enabled
- [ ] Resource limits set (CPU, memory)

### For Validators (Additional)
- [ ] **100,000 QRDX staked** on-chain
- [ ] Validator keys generated and backed up securely
- [ ] Keys mounted as read-only volume
- [ ] Uptime monitoring (99%+ required)
- [ ] Slashing protection enabled
- [ ] Only ONE instance running (prevent double-signing)
- [ ] Network latency optimized (<50ms to peers)
- [ ] Alert system for missed attestations

---

## Troubleshooting

### Node won't sync
```bash
# Check peers
docker exec qrdx-node trinity --help
# Ensure port 30303 is accessible
telnet your-node-ip 30303
```

### Validator not producing blocks
```bash
# Check if keys are loaded
docker exec qrdx-validator ls -la /root/.local/share/trinity/validator_keys

# Verify stake registered on-chain
# Call StakeTracker.getValidator(your_address)
```

### Slashing occurred
- Review logs for double-signing incidents
- Check network connectivity (downtime)
- Ensure only one validator instance running

---

## Building from Source

```bash
# Clone repository
git clone https://github.com/qrdx-org/qrdx-chain.git
cd qrdx-chain

# Build node
docker build -f docker/Dockerfile.node -t qrdx-node:latest .

# Build validator
docker build -f docker/Dockerfile.validator -t qrdx-validator:latest .

# Push to registry
docker tag qrdx-node:latest ghcr.io/qrdx-org/qrdx-node:latest
docker push ghcr.io/qrdx-org/qrdx-node:latest

docker tag qrdx-validator:latest ghcr.io/qrdx-org/qrdx-validator:latest
docker push ghcr.io/qrdx-org/qrdx-validator:latest
```

---

## Support

- **Documentation**: https://docs.qrdx.org
- **Discord**: https://discord.gg/qrdx
- **GitHub Issues**: https://github.com/qrdx-org/qrdx-chain/issues
- **Validator Support**: validator-support@qrdx.org

---

## License

QRDX Chain is licensed under MIT. See [LICENSE](../LICENSE) for details.
