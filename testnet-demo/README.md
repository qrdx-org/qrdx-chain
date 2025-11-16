# QR-PoS Testnet

Quantum-Resistant Proof-of-Stake testnet with 4 validators.

## Network Information

- **Chain ID**: 1337
- **Consensus**: QR-PoS (Quantum-Resistant Proof-of-Stake)
- **Validators**: 4
- **Slot Duration**: 2 seconds
- **Slots Per Epoch**: 32
- **Epoch Duration**: 64 seconds

## Validators

### Validator 0
- **PQ Address**: `qrdx1pcdwaq83x2l8ygfr7wa9ghvusgcgkeehr7q7ztldvt63cq93ktfvsej6n76`
- **Stake**: 32000 QRDX
- **RPC**: http://localhost:8545
- **WS**: ws://localhost:8546
- **Keystore**: `validators/validator_0.json`

### Validator 1
- **PQ Address**: `qrdx1pl87fykknwe2sdj53m5unq7a7zxz6uaxk0lx2ns8rd2tmp6ysvf3shya356`
- **Stake**: 32000 QRDX
- **RPC**: http://localhost:8546
- **WS**: ws://localhost:8547
- **Keystore**: `validators/validator_1.json`

### Validator 2
- **PQ Address**: `qrdx1psk97lac76nmtgxktd7j0lwrjcwplr357gcmuw3g747t3nmu9654q6k3yze`
- **Stake**: 32000 QRDX
- **RPC**: http://localhost:8547
- **WS**: ws://localhost:8548
- **Keystore**: `validators/validator_2.json`

### Validator 3
- **PQ Address**: `qrdx1petl7zfwxvh2nj98hwhfxeumc8ekwpg9j2dlfxsxh9d9u2d25yqrqhryywm`
- **Stake**: 32000 QRDX
- **RPC**: http://localhost:8548
- **WS**: ws://localhost:8549
- **Keystore**: `validators/validator_3.json`


## Test Accounts

5 prefunded accounts with 1000000 ETH each:

- Account 0: `qrdx1py0ht66xn2mq6wqpzru2yqs76v3gz760l5xjvx2w82rdufjys72ysruuslp`
- Account 1: `qrdx1p7grj3hgst3cs8y0gh4awtu9lv86s52v206gt3xa4zrk5mrygm6tqkrzz3g`
- Account 2: `qrdx1phz8my92kgyvn0mf8v7qvu9a5ljm4rune9mf5m0yw0ljrn30rd4rsfylpr5`
- Account 3: `qrdx1pj0mg7kcha5qc8r3m7l3cqgw8x298w63qp9p2ku05h9fc0ylmwresvuvayw`
- Account 4: `qrdx1pf2dpt2xxcq303qx8qcslhespdejknru70vfau5sg70lhz0ez3nnsd83pkl`

## Quick Start

### Start the testnet

```bash
./start-testnet.sh
```

### View logs

```bash
docker-compose logs -f
docker-compose logs -f validator-0  # Single validator
```

### Stop the testnet

```bash
./stop-testnet.sh
```

### Reset and start fresh

```bash
./reset-testnet.sh
./start-testnet.sh
```

## Connecting to the Testnet

### Using Web3.py

```python
from web3 import Web3

# Connect to validator 0
w3 = Web3(Web3.HTTPProvider('http://localhost:8545'))

# Check connection
print(f"Connected: {w3.is_connected()}")
print(f"Chain ID: {w3.eth.chain_id}")
print(f"Block number: {w3.eth.block_number}")
```

### Using curl

```bash
# Get latest block
curl -X POST http://localhost:8545 \
  -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","method":"eth_blockNumber","params":[],"id":1}'

# Get validator info
curl -X POST http://localhost:8545 \
  -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","method":"eth_getValidatorInfo","params":["0x..."],"id":1}'
```

## Sending Transactions

### Load test account keys

```python
import json
from trinity.crypto.pq.dilithium import DilithiumPrivateKey

# Load a test account
with open('keys/test_account_0.json') as f:
    keystore = json.load(f)

private_key_bytes = bytes.fromhex(keystore['crypto']['ciphertext'])
public_key_bytes = bytes.fromhex(keystore['public_key'])

privkey = DilithiumPrivateKey.from_bytes(private_key_bytes, public_key_bytes)
```

### Send PQ transaction

```python
# Build transaction
tx = {
    'from': keystore['pq_address'],
    'to': recipient_address,
    'value': w3.to_wei(10, 'ether'),
    'gas': 21000,
    'gasPrice': w3.eth.gas_price,
    'nonce': w3.eth.get_transaction_count(keystore['pq_address']),
}

# Sign with Dilithium
signed_tx = privkey.sign(encode_transaction(tx))

# Send transaction
tx_hash = w3.eth.send_raw_transaction(signed_tx)
print(f"Transaction hash: {tx_hash.hex()}")
```

## Directory Structure

```
{self.output_dir.name}/
├── genesis/
│   └── genesis.json          # Genesis configuration
├── validators/
│   ├── validator_0.json      # Validator keystores
│   ├── validator_1.json
│   └── ...
├── keys/
│   ├── validator_keys.json   # All validator keys
│   └── test_accounts.json    # All test account keys
├── config/
│   └── trinity.json          # Trinity configuration
├── docker-compose.yml        # Multi-node setup
├── start-testnet.sh          # Start script
├── stop-testnet.sh           # Stop script
├── reset-testnet.sh          # Reset script
└── README.md                 # This file
```

## Security Notice

⚠️ **WARNING**: This testnet uses unencrypted keystores for convenience.
**NEVER** use these keys or this setup for mainnet or with real value!

All private keys are stored in plaintext in the `validators/` and `keys/` directories.

## Monitoring

### Check validator status

```bash
# Check if validator is proposing blocks
docker-compose logs validator-0 | grep "Proposed block"

# Check attestations
docker-compose logs validator-0 | grep "Attestation"

# Check finality
docker-compose logs validator-0 | grep "Finalized"
```

### Network statistics

```bash
# Get validator count
curl -X POST http://localhost:8545 \
  -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","method":"eth_getValidatorCount","params":[],"id":1}'

# Get finalized epoch
curl -X POST http://localhost:8545 \
  -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","method":"eth_getFinalizedEpoch","params":[],"id":1}'
```

## Troubleshooting

### Validators not proposing blocks

- Check validator keystores are mounted correctly
- Verify genesis validators match keystore public keys
- Check logs for slashing or network issues

### Cannot connect to RPC

- Ensure ports are not already in use
- Check firewall settings
- Verify Docker containers are running: `docker-compose ps`

### Finality not progressing

- Ensure at least 2/3 of validators are online
- Check for network partitions
- Verify validator attestations in logs

## Support

For issues or questions:
- GitHub: https://github.com/qrdx-org/qrdx-chain
- Documentation: https://docs.qrdx.org

---

Generated: {time.strftime('%Y-%m-%d %H:%M:%S UTC', time.gmtime())}
Chain ID: {self.chain_id}
Validators: {self.num_validators}
