# QRDX Bridge Relay Service

**Standalone service for ETH<->QRDX bridge validators**

This service monitors both Ethereum and QRDX chains for bridge deposits and relays cross-chain transfer confirmations with quantum-resistant Dilithium signatures.

## Architecture

The bridge relay is **separate from the QRDX chain itself** and acts as an independent validator service that:

1. **Monitors Ethereum** via Infura/Alchemy or local node
2. **Monitors QRDX** via local QRDX node RPC
3. **Detects deposits** on both chains
4. **Signs transfers** with Dilithium (quantum-resistant)
5. **Submits confirmations** to the target chain

```
┌─────────────────┐         ┌──────────────────┐         ┌─────────────────┐
│  Ethereum Node  │◄────────┤  Bridge Relay    ├────────►│   QRDX Node     │
│  (via Infura)   │         │  (Validator)     │         │  (Local RPC)    │
└─────────────────┘         └──────────────────┘         └─────────────────┘
        │                            │                            │
        │                            │                            │
        ▼                            ▼                            ▼
  ETH Bridge                   Dilithium                    QRDX Bridge
  Contract                     Signatures                   Contract
```

## Requirements

### System Requirements
- Python 3.8+
- 4GB RAM minimum
- Stable internet connection
- Access to Ethereum RPC (Infura/Alchemy recommended)
- Access to QRDX node RPC

### Python Dependencies
```bash
pip install web3>=6.0.0 eth-account>=0.8.0 hexbytes>=0.3.0
```

### Crypto Dependencies (from QRDX Phase 1-6)
- `liboqs-python>=0.9.0` (Dilithium signatures)
- `blake3>=0.4.0` (BLAKE3 hashing)

## Installation

### 1. Install Dependencies
```bash
cd trinity/components
pip install -r bridge_relay_requirements.txt
```

### 2. Generate Dilithium Keys
```python
from eth.crypto.dilithium import DilithiumKeypair

# Generate new keypair
keypair = DilithiumKeypair.generate()

# Save private key (4000 bytes)
with open('dilithium_key.bin', 'wb') as f:
    f.write(keypair.private_key())

# Save public key (1952 bytes) 
with open('dilithium_key.pub', 'wb') as f:
    f.write(keypair.public_key())

print(f"Dilithium keys generated!")
```

### 3. Configure Service

Copy the example configuration:
```bash
cp bridge_relay_config.example.json bridge_relay_config.json
```

Edit `bridge_relay_config.json`:
```json
{
  "eth_rpc_url": "https://mainnet.infura.io/v3/YOUR_INFURA_PROJECT_ID",
  "qrdx_rpc_url": "http://localhost:8546",
  "bridge_eth_address": "0x...",  // Deployed Ethereum bridge
  "bridge_qrdx_address": "0x...",  // Deployed QRDX bridge
  "validator_eth_key": "0x...",  // Your ETH private key
  "validator_dilithium_key": "dilithium_key.bin",
  "bridge_abi_file": "contracts/bridge/QRDXBridge_abi.json"
}
```

### 4. Register as Validator

Register your validator address and Dilithium public key with both bridge contracts:

```python
from web3 import Web3
from eth_account import Account

# Connect to chains
eth_w3 = Web3(Web3.HTTPProvider('https://mainnet.infura.io/v3/YOUR_KEY'))
bridge = eth_w3.eth.contract(address=bridge_address, abi=bridge_abi)

# Load keys
account = Account.from_key(eth_private_key)
with open('dilithium_key.pub', 'rb') as f:
    dilithium_public_key = f.read()

# Register (requires 100 ETH stake)
tx = bridge.functions.addValidator(
    account.address,
    dilithium_public_key,
    eth_w3.to_wei(100, 'ether')
).transact({
    'from': account.address,
    'value': eth_w3.to_wei(100, 'ether')
})

print(f"Registered as validator: {tx.hex()}")
```

Repeat for QRDX bridge.

## Usage

### Start the Relay Service

```bash
python bridge_relay.py bridge_relay_config.json
```

Or using environment variables:
```bash
export ETH_RPC_URL="https://mainnet.infura.io/v3/YOUR_KEY"
export QRDX_RPC_URL="http://localhost:8546"
export BRIDGE_ETH_ADDRESS="0x..."
export BRIDGE_QRDX_ADDRESS="0x..."
export VALIDATOR_ETH_KEY="0x..."
export VALIDATOR_DILITHIUM_KEY="dilithium_key.bin"

python bridge_relay.py
```

### Monitor Logs

The service will output:
```
======================================================================
               QRDX BRIDGE RELAY SERVICE
======================================================================
✅ Connected to Ethereum: https://mainnet.infura.io/v3/...
   Chain ID: 1
   Latest block: 18500000

✅ Connected to QRDX: http://localhost:8546
   Chain ID: 7843
   Latest block: 1250000

🔑 Validator ETH address: 0x742d35Cc6634C0532925a3b844Bc9e7595f0bEb
📄 Ethereum bridge: 0x...
📄 QRDX bridge: 0x...
🔐 Dilithium signer initialized

🚀 Starting relay service...

🔍 Monitoring Ethereum chain for deposits...
   Starting from block 18500000

🔍 Monitoring QRDX chain for deposits...
   Starting from block 1250000

📥 Ethereum: Blocks 18500001-18500010, found 1 deposit(s)
💸 New transfer: 0xa1b2c3...
   From: 0x123...
   To: 0x456...
   Amount: 1000000000000000000
   ethereum → qrdx
🌳 Generated Merkle proof (8 nodes)
✍️  Signed with Dilithium (3309 bytes)
✅ Submitted confirmation to qrdx: 0xdef456...
   Gas used: 150,000
```

### Running as a Service (Linux)

Create systemd service file `/etc/systemd/system/qrdx-bridge-relay.service`:
```ini
[Unit]
Description=QRDX Bridge Relay Service
After=network.target

[Service]
Type=simple
User=validator
WorkingDirectory=/opt/qrdx-bridge-relay
ExecStart=/usr/bin/python3 bridge_relay.py bridge_relay_config.json
Restart=always
RestartSec=10

[Install]
WantedBy=multi-user.target
```

Enable and start:
```bash
sudo systemctl enable qrdx-bridge-relay
sudo systemctl start qrdx-bridge-relay
sudo systemctl status qrdx-bridge-relay
```

View logs:
```bash
sudo journalctl -u qrdx-bridge-relay -f
```

## Configuration Options

### RPC Endpoints

**Ethereum Options:**
- **Infura**: `https://mainnet.infura.io/v3/YOUR_PROJECT_ID` (recommended)
- **Alchemy**: `https://eth-mainnet.g.alchemy.com/v2/YOUR_API_KEY`
- **Local Geth**: `http://localhost:8545`
- **Local Erigon**: `http://localhost:8545`

**QRDX:**
- **Local Node**: `http://localhost:8546` (default QRDX RPC port)
- **Remote Node**: `https://rpc.qrdx.network` (if available)

### Performance Tuning

**For High-Volume Validators:**
1. Use local Ethereum archive node instead of Infura
2. Increase Python async worker pool size
3. Use PostgreSQL for transfer tracking (instead of in-memory)
4. Add Redis for caching

**For Low-Latency:**
1. Co-locate with QRDX node (same datacenter)
2. Use WebSocket instead of HTTP for RPC
3. Batch signature verifications

## Security

### Key Management

**NEVER expose your private keys!**

1. **Dilithium Key**: 
   - Store in secure location (e.g., `/etc/qrdx/dilithium_key.bin`)
   - Set permissions: `chmod 600 dilithium_key.bin`
   - Backup securely (encrypted)

2. **Ethereum Key**:
   - Use hardware wallet (Ledger/Trezor) in production
   - Or use key management service (AWS KMS, HashiCorp Vault)
   - Never commit to git

3. **Configuration File**:
   - Set permissions: `chmod 600 bridge_relay_config.json`
   - Use environment variables in production

### Network Security

1. **Firewall**:
   - Only allow outbound to RPC endpoints
   - Block all inbound except monitoring

2. **RPC Authentication**:
   - Use authenticated Infura/Alchemy endpoints
   - Use TLS for all connections

3. **Monitoring**:
   - Set up alerts for failed confirmations
   - Monitor validator balance (gas fees)
   - Track confirmation latency

## Monitoring

### Key Metrics

1. **Deposits Detected**: Number of deposits seen per hour
2. **Confirmations Submitted**: Number of confirmations sent
3. **Confirmation Latency**: Time from deposit to confirmation
4. **Failed Transactions**: Number of failed confirmation attempts
5. **Gas Used**: Total gas consumed by confirmations
6. **Validator Balance**: Remaining ETH/QRDX for gas

### Prometheus Integration

Add metrics endpoint:
```python
from prometheus_client import Counter, Gauge, start_http_server

deposits_total = Counter('bridge_deposits_total', 'Total deposits detected')
confirmations_total = Counter('bridge_confirmations_total', 'Total confirmations submitted')
confirmation_latency = Gauge('bridge_confirmation_latency_seconds', 'Confirmation latency')

# Start metrics server
start_http_server(9090)
```

### Grafana Dashboard

Example queries:
```
# Deposits per hour
rate(bridge_deposits_total[1h]) * 3600

# Confirmation success rate
rate(bridge_confirmations_total{status="success"}[5m]) / 
rate(bridge_confirmations_total[5m])

# Average confirmation latency
avg(bridge_confirmation_latency_seconds)
```

## Troubleshooting

### "Cannot connect to Ethereum RPC"

**Cause**: Invalid Infura key or network issue

**Solution**:
1. Verify Infura project ID is correct
2. Check internet connection
3. Try alternative RPC (Alchemy, local node)
4. Check firewall rules

### "Transaction failed: insufficient gas"

**Cause**: Gas price too low or out of ETH

**Solution**:
1. Check validator ETH balance
2. Increase gas price in configuration
3. Top up validator account

### "Dilithium signature verification failed"

**Cause**: Wrong Dilithium key or corrupted signature

**Solution**:
1. Verify Dilithium key file is correct
2. Re-generate keys if corrupted
3. Update validator registration with new public key

### "Transfer not found on target chain"

**Cause**: Transfer hasn't been created yet or wrong chain

**Solution**:
1. Wait for source chain confirmation
2. Verify bridge contract addresses
3. Check chain IDs match

## FAQ

### Q: Can I run multiple relays with the same validator?
**A**: Yes, but they must use the same Dilithium key. Multiple relays will submit duplicate confirmations (harmless, but wastes gas).

### Q: How much does it cost to run a relay?
**A**: Gas costs depend on transfer volume:
- Low volume (1-10 transfers/day): ~$5-50/month
- Medium volume (100 transfers/day): ~$500/month
- High volume (1000+ transfers/day): ~$5,000/month

Plus 100 ETH validator stake (~$300,000 @ $3000/ETH).

### Q: What happens if my relay goes offline?
**A**: Other validators will continue confirming transfers. Your validator won't earn rewards during downtime. If offline >24 hours, may face penalties.

### Q: Can I use a testnet for testing?
**A**: Yes! Use Goerli testnet:
```json
{
  "eth_rpc_url": "https://goerli.infura.io/v3/YOUR_KEY",
  "qrdx_rpc_url": "http://localhost:8546",
  ...
}
```

### Q: How do I update my validator key?
**A**: 
1. Generate new Dilithium keypair
2. Call `updateValidator()` on bridge contracts
3. Update relay configuration
4. Restart relay service

## Support

- **Documentation**: `/docs/bridge/`
- **GitHub Issues**: https://github.com/qrdx-org/qrdx-chain/issues
- **Discord**: https://discord.gg/qrdx
- **Email**: validators@qrdx.network

## License

MIT License - See LICENSE file for details
