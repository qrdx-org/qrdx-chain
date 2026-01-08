# QRDX Node Bootstrap and Genesis Updates

## Overview

This update adds two key features to the QRDX node:

1. **Bootstrap from Multiple Nodes** - Nodes can now bootstrap from a configurable list of bootstrap nodes instead of a single hardcoded node
2. **Prefunded Genesis Accounts** - Genesis block initialization with pre-allocated balances for treasury, foundation, and other accounts

## Changes Summary

### 1. Bootstrap Node List (`qrdx/constants.py`)

Added support for multiple bootstrap nodes via environment configuration:

```python
# Environment variable (comma-separated)
QRDX_BOOTSTRAP_NODES='http://node.qrdx.network,http://node2.qrdx.network,http://node3.qrdx.network'

# Or in .env file
QRDX_BOOTSTRAP_NODES=http://node.qrdx.network,http://node2.qrdx.network,http://node3.qrdx.network
```

The `BOOTSTRAP_NODES` constant is parsed from this and used throughout the node.

### 2. Bootstrap Manager (`qrdx/node/bootstrap.py`)

New module providing:

- `BootstrapManager` class with health tracking for each bootstrap node
- Automatic failover between bootstrap nodes
- Peer discovery aggregation from multiple sources
- Statistics and monitoring capabilities

Key methods:
- `bootstrap()` - Bootstrap from all available nodes
- `get_best_bootstrap_node()` - Get the healthiest/fastest bootstrap node
- `check_node_health()` - Health check a specific node

### 3. NodesManager Updates (`qrdx/node/nodes_manager.py`)

Added bootstrap-related methods:

- `bootstrap_from_nodes(client, handshake_func)` - Bootstrap from configured nodes
- `get_bootstrap_nodes()` - Get list of configured bootstrap nodes
- `set_bootstrap_nodes(nodes)` - Update bootstrap node list dynamically
- `add_bootstrap_node(url)` - Add a new bootstrap node
- `is_bootstrap_complete()` - Check if initial bootstrap completed
- `reset_bootstrap()` - Reset bootstrap state

### 4. Main Node Updates (`qrdx/node/main.py`)

Updated peer discovery to use multiple bootstrap nodes:

- New `bootstrap_from_all_nodes()` function attempts handshakes with all bootstrap nodes
- `periodic_peer_discovery()` now re-bootstraps from all nodes when peer list is empty
- `check_own_reachability()` tries multiple bootstrap nodes to verify public reachability

### 5. Genesis Prefunded Accounts (`qrdx/constants.py`)

Added genesis account configuration:

```python
GENESIS_PREFUNDED_ACCOUNTS = {
    # Treasury - ecosystem development, grants, partnerships
    'Qrdx_treasury_00000000000000000000000000000001': (Decimal('10000000'), 'Treasury'),
    
    # Foundation - long-term development and maintenance
    'Qrdx_foundation_000000000000000000000000000001': (Decimal('5000000'), 'Foundation'),
    
    # Validator incentive fund - bootstrapping initial validators
    'Qrdx_validator_incentive_0000000000000000001': (Decimal('2000000'), 'Validator Incentive Fund'),
    
    # Community fund - airdrops, community initiatives
    'Qrdx_community_fund_00000000000000000000001': (Decimal('3000000'), 'Community Fund'),
}

GENESIS_TOTAL_PREFUNDED = 20_000_000  # 20M QRDX
```

### 6. Genesis Initialization (`qrdx/validator/genesis_init.py`)

New module for database initialization with genesis state:

- `GenesisInitializer` class handles full genesis setup
- `initialize_genesis_if_needed(db)` - Convenience function for startup
- Creates genesis block, prefunded account outputs, and initial validator records
- Supports both mainnet and testnet configurations

Key features:
- Checks if genesis initialization is needed (block height = 0)
- Creates spendable UTXO outputs for prefunded accounts
- Stores genesis metadata for chain verification

### 7. Configuration Updates (`config.example.toml`)

Added comprehensive genesis and bootstrap configuration:

```toml
[p2p.discovery]
bootnodes = [
    "http://node.qrdx.network:3007",
    "http://node2.qrdx.network:3007",
    "http://node3.qrdx.network:3007",
]

[genesis]
chain_id = 1
network_name = "qrdx-mainnet"
initial_supply = 100000000

[genesis.prefunded_accounts]
"Qrdx_treasury_00000000000000000000000000000001" = [10000000, "Treasury"]
"Qrdx_foundation_000000000000000000000000000001" = [5000000, "Foundation"]
# ... more accounts
```

## Usage

### Configuring Bootstrap Nodes

**Option 1: Environment Variable**
```bash
export QRDX_BOOTSTRAP_NODES="http://node1.example.com:3007,http://node2.example.com:3007"
python run_node.py
```

**Option 2: .env File**
```
QRDX_BOOTSTRAP_NODES=http://node1.example.com:3007,http://node2.example.com:3007
```

**Option 3: config.toml**
```toml
[p2p.discovery]
bootnodes = [
    "http://node1.example.com:3007",
    "http://node2.example.com:3007",
]
```

### Initializing Genesis

Genesis is automatically initialized when a node starts with an empty database:

```python
from qrdx.validator.genesis_init import initialize_genesis_if_needed

# In node startup
await initialize_genesis_if_needed(db)
```

For custom prefunded accounts:
```python
from qrdx.validator.genesis_init import GenesisInitializer

initializer = GenesisInitializer(db)
await initializer.initialize_genesis(
    prefunded_accounts={
        'custom_address': (Decimal('1000000'), 'Custom Account'),
    },
    network_name="my-testnet",
    chain_id=9999,
)
```

## Testing

All 38 existing tests continue to pass:

```bash
python -m pytest tests/ -v
# ======================== 38 passed, 1 warning in 1.06s =========================
```

## Files Modified/Created

- **Modified:**
  - `qrdx/constants.py` - Added BOOTSTRAP_NODES and GENESIS_PREFUNDED_ACCOUNTS
  - `qrdx/node/nodes_manager.py` - Added bootstrap methods
  - `qrdx/node/main.py` - Updated peer discovery and reachability check
  - `config.example.toml` - Added genesis and bootstrap configuration

- **Created:**
  - `qrdx/node/bootstrap.py` - BootstrapManager class
  - `qrdx/validator/genesis_init.py` - Genesis database initialization

## Backward Compatibility

- The old `DENARO_BOOTSTRAP_NODE` constant is still available for backward compatibility
- If `QRDX_BOOTSTRAP_NODES` is not set, the system falls back to the single bootstrap node
- Existing node configurations continue to work without changes
