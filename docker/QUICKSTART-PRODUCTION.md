# Quick Start Guide - QRDX Docker Containers

## Two Container Types

### 1️⃣ **qrdx-node** - Full Node (No Validation)
- Syncs blockchain
- Serves RPC requests
- No stake required
- No validator keys needed

### 2️⃣ **qrdx-validator** - Validator Node
- Everything a full node does PLUS:
- Proposes blocks
- Signs attestations
- Earns rewards
- **Requires 100,000 QRDX stake**
- **Requires Dilithium keys**

---

## Quick Commands

### Build Both Images
```bash
# Build node
docker build -f docker/Dockerfile.node -t qrdx-node:latest .

# Build validator
docker build -f docker/Dockerfile.validator -t qrdx-validator:latest .
```

### Run Full Node
```bash
docker run -d \
  --name qrdx-node \
  -p 30303:30303 \
  -p 8545:8545 \
  -v qrdx-node-data:/root/.local/share/trinity \
  qrdx-node:latest
```

### Run Validator
```bash
# First, generate or copy your validator keys to a directory
# Then run with keys mounted:
docker run -d \
  --name qrdx-validator \
  -p 30303:30303 \
  -p 8545:8545 \
  -v /path/to/validator_keys:/root/.local/share/trinity/validator_keys:ro \
  -v qrdx-validator-data:/root/.local/share/trinity \
  qrdx-validator:latest
```

### Using Docker Compose
```bash
# Edit docker-compose.production.yml to set your validator keys path
# Then start both:
docker-compose -f docker/docker-compose.production.yml up -d

# Or just node:
docker-compose -f docker/docker-compose.production.yml up -d qrdx-node

# Or just validator:
docker-compose -f docker/docker-compose.production.yml up -d qrdx-validator
```

---

## Validator Requirements Checklist

Before running validator, ensure you have:

- [ ] **100,000 QRDX** staked via StakeTracker contract
- [ ] **Dilithium keypair** generated (1,952 byte public key)
- [ ] **Validator keys** saved in secure directory
- [ ] **Keys mounted** as read-only volume
- [ ] **Uptime monitoring** setup (99%+ required)
- [ ] **Only ONE instance** running (avoid double-signing)

---

## Production Checklist

### For All Nodes
- [ ] Firewall configured (allow 30303, restrict 8545/8546)
- [ ] Persistent volumes for blockchain data
- [ ] Monitoring and alerting enabled
- [ ] Automatic restart configured
- [ ] Log rotation enabled

### For Validators (Additional)
- [ ] Stake confirmed on-chain (100k QRDX)
- [ ] Keys backed up in multiple secure locations
- [ ] Slashing protection enabled
- [ ] Network latency optimized (<50ms to peers)
- [ ] Resource limits set (8 CPU, 16GB RAM minimum)

---

## Build & Push to Registry

### Build
```bash
docker build -f docker/Dockerfile.node -t qrdx-node:latest .
docker build -f docker/Dockerfile.validator -t qrdx-validator:latest .
```

### Push Both
```bash
export GITHUB_TOKEN=ghp_your_token
export GITHUB_USER=your_username

./docker/push-both-to-ghcr.sh latest qrdx-org/qrdx-chain both
```

### Push Individual
```bash
# Just node
./docker/push-both-to-ghcr.sh latest qrdx-org/qrdx-chain node

# Just validator
./docker/push-both-to-ghcr.sh latest qrdx-org/qrdx-chain validator
```

---

## Key Differences

| Feature | qrdx-node | qrdx-validator |
|---------|-----------|----------------|
| Sync blockchain | ✅ | ✅ |
| RPC server | ✅ | ✅ |
| Propose blocks | ❌ | ✅ |
| Earn rewards | ❌ | ✅ |
| Stake required | 0 | 100,000 QRDX |
| Validator keys | No | **Yes (Required)** |
| Slashing risk | None | Yes |
| CPU required | 4 cores | 8+ cores |
| RAM required | 8 GB | 16+ GB |

---

## Troubleshooting

### Node won't start
```bash
# Check logs
docker logs qrdx-node

# Check ports
netstat -tuln | grep -E '30303|8545|8546'
```

### Validator keys not found
```bash
# Verify keys are mounted
docker exec qrdx-validator ls -la /root/.local/share/trinity/validator_keys

# Should see:
# validator_private_key.pem
# validator_public_key.pem
```

### Not proposing blocks
- Verify stake registered: Check StakeTracker contract
- Check validator status: Should be ACTIVE, not PENDING
- Ensure network connectivity to peers
- Verify uptime > 90%

---

## Support

See [README-PRODUCTION.md](README-PRODUCTION.md) for complete documentation.

- **Docs**: https://docs.qrdx.org
- **Discord**: https://discord.gg/qrdx
- **Issues**: https://github.com/qrdx-org/qrdx-chain/issues
