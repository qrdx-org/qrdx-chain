# QRDX Testnet Quick Reference

## One-Line Commands

```bash
# Start default testnet (4 nodes, 2 validators)
./scripts/testnet.sh start

# Start custom testnet
./scripts/testnet.sh start --nodes 6 --validators 3

# Check status
./scripts/testnet.sh status

# View logs (node 0)
./scripts/testnet.sh logs 0

# Stop all nodes
./scripts/testnet.sh stop

# Complete cleanup
./scripts/testnet.sh clean
```

## Network Endpoints

| Node | Role | API Port | RPC Port | WebSocket |
|------|------|----------|----------|-----------|
| 0 | Bootstrap + Validator | 3007 | 8545 | 8546 |
| 1 | Validator | 3008 | 8546 | 8547 |
| 2 | Regular | 3009 | 8547 | 8548 |
| 3 | Regular | 3010 | 8548 | 8549 |

## Quick Tests

```bash
# Get block height
curl -s http://127.0.0.1:3007/get_status | jq .result.height

# Get validators
curl -s http://127.0.0.1:3007/validators | jq

# Get peers
curl -s -X POST http://127.0.0.1:3007/get_peers | jq

# Watch blocks
watch -n 2 'curl -s http://127.0.0.1:3007/get_status | jq .result.height'
```

## File Locations

```
testnet/
├── wallets/validator_0.json    # Validator 0 wallet
├── wallets/validator_1.json    # Validator 1 wallet
├── configs/node0.env           # Node 0 configuration
├── logs/node0/node.log         # Node 0 logs
└── genesis_config.json         # Genesis state
```

## Database Access

```bash
# Connect to node 0 database
psql -h localhost -U qrdx -d qrdx_testnet_node0

# Useful queries
SELECT * FROM validators;
SELECT id, hash, slot, epoch FROM blocks ORDER BY id DESC LIMIT 10;
SELECT * FROM epochs ORDER BY epoch DESC LIMIT 5;
```

## Common Issues

| Issue | Solution |
|-------|----------|
| Port already in use | `lsof -i :3007` then kill process |
| PostgreSQL not running | `sudo systemctl start postgresql` |
| Node won't start | Check `./scripts/testnet.sh logs 0` |
| Genesis error | `./scripts/testnet.sh clean` and retry |

## Environment Variables

```bash
# Customize database user
export POSTGRES_USER=myuser
export POSTGRES_PASSWORD=mypass

# Start testnet
./scripts/testnet.sh start
```
