# QRDX Local Testnet

Professional testnet deployment script for QRDX Chain development and testing.

## Features

- **Configurable Network Size**: Spin up any number of nodes and validators
- **Automatic Wallet Generation**: Creates PQ (Dilithium3) wallets for validators
- **Genesis Configuration**: Automatic genesis block creation with prefunded validators
- **Database Management**: Creates an isolated SQLite database per node
- **Process Management**: Start, stop, and monitor all nodes
- **Professional Logging**: Centralized logs with per-node directories
- **Full Mesh**: Every node bootstraps from every other node, so blocks reach each peer directly
- **250 ms Blocks**: The standard slot (`--slot-ms` to change it)

## Quick Start

```bash
# Start testnet with defaults (4 nodes, 2 validators)
./scripts/testnet.sh start

# Check status
./scripts/testnet.sh status

# View logs
./scripts/testnet.sh logs 0

# Stop testnet
./scripts/testnet.sh stop
```

## Requirements

- Python 3.8+
- PostgreSQL 12+
- jq (JSON processor)
- Standard Unix tools (bash, ps, kill)

### Install Dependencies

**Ubuntu/Debian:**
```bash
sudo apt-get update
sudo apt-get install postgresql postgresql-client python3 python3-pip jq
```

**macOS:**
```bash
brew install postgresql python3 jq
```

## Usage

### Start Testnet

```bash
# Default configuration (4 nodes, 2 validators)
./scripts/testnet.sh start

# Custom configuration
./scripts/testnet.sh start --nodes 6 --validators 3

# Minimum configuration (2 nodes, 1 validator)
./scripts/testnet.sh start --nodes 2 --validators 1
```

**Default Configuration:**
- **Nodes**: 4
- **Validators**: 2 (node 0 and node 1)
- **Slot**: 250 ms (32-slot, 8 s epochs)
- **Peers**: every node lists every other node as a bootstrap peer
- **Genesis Balance**: 1,000,000 QRDX per validator
- **Validator Stake**: 100,000 QRDX per validator
- **Base Port**: 3007

### Network Topology

```
  Node 0 (Validator 0)  ◄──────►  Node 1 (Validator 1)
  Port 3007, RPC 8545             Port 3008, RPC 8546
        ▲   ╲                    ╱   ▲
        │     ╲                ╱     │
        │       ╲ ◄──────► ╱         │
        ▼         ╱      ╲           ▼
  Node 2  ◄──────►         ◄──────►  Node 3
  Port 3009, RPC 8547             Port 3010, RPC 8548
```

Every node lists every other node as a bootstrap peer. A peer that only connects in is recorded
without a URL, and blocks are pushed only to peers with one, so with a single bootstrap node
some validators received each other's blocks late or not at all, and at 250 ms slots they
forked. All nodes start together and genesis is set 15 s or more ahead, so the mesh has formed
before the first slot.

### Check Status

```bash
./scripts/testnet.sh status
```

Output:
```
==> QRDX Local Testnet Status

[INFO] Slot: 250 ms

● Node 0 - RUNNING (PID: 12345, Port: 3007, RPC: 8545) [healthy] height 520
● Node 1 - RUNNING (PID: 12346, Port: 3008, RPC: 8546) [healthy] height 520
● Node 2 - RUNNING (PID: 12347, Port: 3009, RPC: 8547) [healthy] height 520
● Node 3 - RUNNING (PID: 12348, Port: 3010, RPC: 8548) [healthy] height 520

[INFO] Running: 4 nodes
```

### View Logs

```bash
# View logs for node 0 (bootstrap)
./scripts/testnet.sh logs 0

# View logs for node 1 (validator)
./scripts/testnet.sh logs 1

# View all logs in separate terminals
for i in {0..3}; do
    gnome-terminal -- bash -c "./scripts/testnet.sh logs $i; exec bash"
done
```

### Stop Testnet

```bash
# Gracefully stop all nodes
./scripts/testnet.sh stop
```

### Clean Up

```bash
# Stop nodes and remove all testnet data
./scripts/testnet.sh clean
```

**Warning**: This removes all testnet data including wallets, databases, and logs.

## Directory Structure

```
testnet/
├── configs/          # Node configuration files
│   ├── node0.env
│   ├── node1.env
│   └── ...
├── data/             # Node data directories
│   ├── node0/
│   ├── node1/
│   └── ...
├── logs/             # Log files
│   ├── node0/
│   │   └── node.log
│   ├── node1/
│   │   └── node.log
│   └── ...
├── wallets/          # Validator wallets
│   ├── validator_0.json
│   ├── validator_1.json
│   └── ...
├── pids/             # Process ID files
│   ├── node0.pid
│   ├── node1.pid
│   └── ...
└── genesis_config.json  # Genesis configuration
```

## Configuration Files

### Node Configuration (`.env`)

Each node has its own environment configuration file:

```bash
# Example: testnet/configs/node0.env
QRDX_NODE_ID=testnet-node-0
QRDX_NETWORK_NAME=qrdx-testnet-local
QRDX_CHAIN_ID=9999
QRDX_NODE_HOST=127.0.0.1
QRDX_NODE_PORT=3007
QRDX_DATABASE_NAME=qrdx_testnet_node0
QRDX_VALIDATOR_ENABLED=true
QRDX_VALIDATOR_WALLET=/path/to/validator_0.json
```

### Validator Wallets

Wallets are generated automatically using Dilithium3 (PQ):

```json
{
  "version": "2.0",
  "type": "pq",
  "algorithm": "dilithium3",
  "address": "Qrdx...",
  "public_key": "hex_encoded_pubkey",
  "private_key": "hex_encoded_privkey",
  "label": "Validator 0",
  "created": "2026-01-08T00:00:00Z"
}
```

## Interacting with the Testnet

### Using curl

```bash
# Get node status
curl http://127.0.0.1:3007/get_status | jq

# Get blockchain height
curl http://127.0.0.1:3007/get_blocks?offset=0&limit=1 | jq

# Get validator info
curl http://127.0.0.1:3007/validators | jq
```

### Using Python

```python
import requests

# Connect to node 0
node_url = "http://127.0.0.1:3007"

# Get status
status = requests.get(f"{node_url}/get_status").json()
print(f"Block height: {status['result']['height']}")

# Get peers
peers = requests.post(f"{node_url}/get_peers").json()
print(f"Connected peers: {len(peers['result']['peers'])}")
```

### Using RPC

```bash
# JSON-RPC on port 8545+
curl -X POST http://127.0.0.1:8545 \
  -H "Content-Type: application/json" \
  -d '{
    "jsonrpc": "2.0",
    "method": "eth_blockNumber",
    "params": [],
    "id": 1
  }' | jq
```

## Advanced Usage

### Custom Genesis Configuration

Modify the genesis parameters in the script:

```bash
# Edit testnet.sh
DEFAULT_GENESIS_BALANCE=2000000  # 2M QRDX per validator
```

### Database Access

```bash
# Connect to node 0 database
psql -h localhost -U qrdx -d qrdx_testnet_node0

# Query validators
SELECT address, stake, status FROM validators;

# Query blocks
SELECT id, hash, proposer_address FROM blocks ORDER BY id DESC LIMIT 10;
```

### Monitor Network Activity

```bash
# Watch block production (node 0)
watch -n 2 'curl -s http://127.0.0.1:3007/get_status | jq .result.height'

# Monitor all nodes
for i in {0..3}; do
  echo "Node $i: $(curl -s http://127.0.0.1:$((3007+i))/get_status | jq -r .result.height)"
done
```

### Test Validator Functionality

```bash
# Check validator status
curl http://127.0.0.1:3007/validators | jq

# Check attestations
curl http://127.0.0.1:3007/attestations | jq

# Check epoch info
curl http://127.0.0.1:3007/epochs/0 | jq
```

## Troubleshooting

### PostgreSQL Connection Issues

```bash
# Check PostgreSQL status
sudo systemctl status postgresql

# Start PostgreSQL
sudo systemctl start postgresql

# Check if listening
pg_isready -h localhost -p 5432
```

### Node Won't Start

```bash
# Check logs
./scripts/testnet.sh logs 0

# Check if port is in use
lsof -i :3007

# Check database connection
psql -h localhost -U qrdx -d qrdx_testnet_node0 -c "SELECT 1"
```

### Validators Not Producing Blocks

```bash
# Check validator wallet
cat testnet/wallets/validator_0.json | jq

# Check validator status in database
psql -h localhost -U qrdx -d qrdx_testnet_node0 \
  -c "SELECT * FROM validators"

# Check node logs for errors
tail -100 testnet/logs/node0/node.log | grep -i error
```

### Clean Start

```bash
# Full cleanup
./scripts/testnet.sh clean

# Drop all databases
for i in {0..9}; do
  psql -h localhost -U qrdx -c "DROP DATABASE IF EXISTS qrdx_testnet_node$i" postgres
done

# Start fresh
./scripts/testnet.sh start
```

## Performance Tuning

### Slot Length

The standard slot is 250 ms (32-slot, 8 s epochs). The slot goes into the genesis chain spec,
which every node reads it from, so set it when starting the testnet:

```bash
./scripts/testnet.sh start --slot-ms 500  # slower slots, e.g. on a loaded machine
```

### Increase Network Size

```bash
# Large testnet
./scripts/testnet.sh start --nodes 10 --validators 5
```

### Database Optimization

```sql
-- Connect to node database
psql -h localhost -U qrdx -d qrdx_testnet_node0

-- Analyze tables
ANALYZE blocks;
ANALYZE transactions;
ANALYZE validators;

-- Vacuum
VACUUM ANALYZE;
```

## Security Notes

⚠️ **This is for local testing only!**

- All wallets use simple passwords (`testnet_validator_N`)
- All nodes run on localhost
- No encryption on inter-node communication
- Genesis accounts are publicly known
- Not suitable for production use

## Contributing

To extend the testnet script:

1. Add new commands in the `cmd_*` functions
2. Update the `show_usage()` function
3. Test with different configurations
4. Update this README

## License

MIT License - See LICENSE file for details

## Support

For issues or questions:
- GitHub Issues: https://github.com/qrdx-org/qrdx-chain/issues
- Documentation: https://docs.qrdx.network
- Discord: https://discord.gg/qrdx
