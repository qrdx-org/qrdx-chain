# QRDX Full Integration Testnet — Design Document

> **Version:** 1.0 · **Date:** March 5, 2026  
> **Author:** QRDX Development Team  
> **Status:** DESIGN PHASE — No code until every section reviewed  
> **Principle:** Zero stubs. Every operation uses real crypto, real databases, real consensus.

---

## Table of Contents

1. [Objectives](#1-objectives)
2. [Architecture Overview](#2-architecture-overview)
3. [Component Inventory — What Exists vs What Must Be Built](#3-component-inventory)
4. [Testnet Genesis & Chain Parameters](#4-testnet-genesis--chain-parameters)
5. [Node Orchestration](#5-node-orchestration)
6. [Wallet & Funding Pipeline](#6-wallet--funding-pipeline)
7. [Transaction Engine](#7-transaction-engine)
8. [Token Operations (qRC20)](#8-token-operations-qrc20)
9. [Exchange & Liquidity Pools](#9-exchange--liquidity-pools)
10. [Validator Lifecycle](#10-validator-lifecycle)
11. [P2P Network Verification](#11-p2p-network-verification)
12. [Governance Operations](#12-governance-operations)
13. [Bridge Operations](#13-bridge-operations)
14. [Integration Test Scenarios](#14-integration-test-scenarios)
15. [Docker Multi-Node Orchestration](#15-docker-multi-node-orchestration)
16. [Monitoring & Observability](#16-monitoring--observability)
17. [Implementation Order](#17-implementation-order)
18. [File Manifest](#18-file-manifest)
19. [Success Criteria](#19-success-criteria)

---

## 1. Objectives

This testnet is **not** a unit test harness. It is a full integration environment that:

1. **Spools up N real nodes** (default: 4) each running the full QRDX FastAPI server with SQLite, PQ identity, and Kademlia DHT.
2. **Forms consensus** — validators propose blocks, create attestations, and finalize epochs using the real PoS validator manager with ML-DSA-65 (Dilithium3) signatures.
3. **Pre-funds wallets** at genesis with real balances tracked in SQLite — PQ wallets for validators, traditional wallets for user simulation, system wallets with their 75M QRDX allocation.
4. **Creates qRC20 tokens** — deploys test tokens with real PQ-signed operations, not in-memory mocks.
5. **Operates liquidity pools** — creates AMM pools, adds liquidity, executes swaps with real fee accounting.
6. **Sends transactions** — UTXO transfers between wallets, verified by all nodes, included in PoS blocks.
7. **Exercises every protocol subsystem** — staking, slashing, governance proposals, bridge simulations, system wallet operations.
8. **Contains zero stubs** — no mock objects, no `return True` bypasses, no in-memory-only state. Every operation persists to SQLite and is verifiable via the RPC/REST API.

### What "Zero Stubs" Means Concretely

| Area | Stub we will NOT use | Real implementation we WILL use |
|------|----------------------|--------------------------------|
| Signatures | `return True` on verify | `oqs.Signature("Dilithium3").verify()` via liboqs |
| Keys | SHA256-padded fake keys | `oqs.Signature("Dilithium3").generate_keypair()` |
| Database | In-memory dicts | SQLite via `aiosqlite` with WAL mode |
| Consensus | Hardcoded block acceptance | ValidatorManager with real selection, attestation, finality |
| Tokens | In-memory QRC20 | QRC20 state persisted to SQLite `token_state` table |
| Pools | In-memory AMM | Pool state persisted to SQLite `pool_state` table |
| P2P | Localhost HTTP only | Full Kademlia DHT with PQ handshake between nodes |
| Wallets | Hardcoded addresses | Real PQ keypair generation + keystore encryption |

---

## 2. Architecture Overview

```
┌─────────────────────────────────────────────────────────────┐
│                    Testnet Orchestrator                       │
│                 (testnet/orchestrator.py)                     │
│                                                               │
│  ┌──────────┐  ┌──────────┐  ┌──────────┐  ┌──────────┐    │
│  │  Node 0  │  │  Node 1  │  │  Node 2  │  │  Node 3  │    │
│  │ Bootstrap │  │Validator │  │Validator │  │  Full    │    │
│  │+Validator │  │          │  │          │  │  Node    │    │
│  │ :3007    │  │ :3008    │  │ :3009    │  │ :3010    │    │
│  └────┬─────┘  └────┬─────┘  └────┬─────┘  └────┬─────┘    │
│       │              │              │              │          │
│       └──────────────┼──────────────┼──────────────┘          │
│                      │              │                          │
│              Kademlia DHT + PQ Handshake                      │
│                                                               │
│  ┌──────────────────────────────────────────────────────┐    │
│  │               Scenario Runner                         │    │
│  │          (testnet/scenarios/*.py)                      │    │
│  │                                                        │    │
│  │  • Wallet funding verification                         │    │
│  │  • UTXO transfer between wallets                       │    │
│  │  • qRC20 token deployment + transfer                   │    │
│  │  • AMM pool creation + swap execution                  │    │
│  │  • Validator staking + block production                │    │
│  │  • Governance proposal lifecycle                       │    │
│  │  • System wallet operations                            │    │
│  │  • Cross-node state consistency checks                 │    │
│  └──────────────────────────────────────────────────────┘    │
│                                                               │
│  ┌──────────────────────────────────────────────────────┐    │
│  │              Health Monitor                            │    │
│  │         (testnet/monitor.py)                           │    │
│  │                                                        │    │
│  │  • Block height tracking per node                      │    │
│  │  • Peer count verification                             │    │
│  │  • Consensus liveness (blocks advancing)               │    │
│  │  • Transaction confirmation latency                    │    │
│  │  • Validator uptime & attestation rate                  │    │
│  └──────────────────────────────────────────────────────┘    │
└─────────────────────────────────────────────────────────────┘
```

---

## 3. Component Inventory

### 3.1 What Exists and Is Real (No Changes Needed)

| Component | Files | Status |
|-----------|-------|--------|
| Node server (FastAPI, 60+ routes) | `qrdx/node/main.py` (4,678 lines) | ✅ Production-quality |
| PQ crypto (Dilithium3, Kyber768) | `qrdx/crypto/pq/dilithium.py`, `kyber.py` | ✅ Real liboqs, no fallback |
| Node identity (ML-DSA-65 + BLAKE3) | `qrdx/node/identity.py` | ✅ Real PQ identity |
| P2P Kademlia DHT | `qrdx/p2p/routing.py`, `discovery.py` | ✅ Full implementation |
| P2P Handshake (4-step PQ) | `qrdx/p2p/handshake.py` | ✅ Real KEM + AES-256-GCM |
| PoS Validator Manager | `qrdx/validator/manager.py` (1,105 lines) | ✅ Real consensus |
| PoS Selection (RANDAO + stake) | `qrdx/validator/selection.py` | ✅ Deterministic |
| Attestation Manager | `qrdx/validator/attestation.py` | ✅ PQ-signed attestations |
| Slashing Detector | `qrdx/validator/slashing.py` | ✅ 5 condition types |
| Epoch Processing | `qrdx/validator/epoch_processing.py` | ✅ Finality + rewards |
| Genesis Creator | `qrdx/validator/genesis.py` | ✅ System wallets + validators |
| SQLite Database | `qrdx/database_sqlite.py` (1,049 lines) | ✅ Full schema |
| UTXO Transactions | `qrdx/transactions/` | ✅ Sign + verify pipeline |
| Wallet v2 (PQ + Traditional) | `qrdx/wallet_v2/` | ✅ Keystore + encryption |
| secp256k1 Classical Keys | `qrdx/crypto/keys.py` | ✅ Ethereum-compatible |
| Constants + Config | `qrdx/constants.py` (858 lines) | ✅ Comprehensive |
| Existing testnet script | `scripts/testnet.sh` (888 lines) | ✅ Node management |

### 3.2 What Exists But Needs Integration Work

| Component | Issue | Required Work |
|-----------|-------|---------------|
| qRC20 Token (`qrdx/tokens/qrc20.py`) | In-memory only, no persistence | Add SQLite persistence layer |
| AMM Engine (`qrdx/exchange/amm.py`) | In-memory only, no persistence | Add SQLite persistence layer |
| Order Book (`qrdx/exchange/orderbook.py`) | In-memory only, no persistence | Add SQLite persistence layer |
| Exchange State Manager (`qrdx/exchange/state_manager.py`) | Exists but not connected to DB | Wire to SQLite |
| Node Integration (`qrdx/node/validator_integration.py`) | Exists, needs testnet verification | Verify slot loop works end-to-end |
| Governance (`qrdx/governance/`) | In-memory proposals | Add SQLite persistence |
| Bridge (`qrdx/bridge/`) | Types/adapters exist | Wire to testnet simulation |

### 3.3 What Must Be Built New

| Component | Purpose | Location |
|-----------|---------|----------|
| Testnet orchestrator (Python) | Programmatic multi-node startup, health checks, scenario execution | `testnet/orchestrator.py` |
| Testnet configuration | Testnet-specific chain params, genesis template | `testnet/config.py` |
| Wallet factory | Create + fund N wallets of each type for test scenarios | `testnet/wallet_factory.py` |
| Transaction sender | Build + sign + broadcast real UTXO transactions | `testnet/tx_sender.py` |
| Token deployer | Deploy qRC20 tokens via real on-chain operations | `testnet/token_deployer.py` |
| Pool operator | Create AMM pools + execute swaps | `testnet/pool_operator.py` |
| Scenario runner | Orchestrate multi-step test scenarios | `testnet/scenarios/` |
| Health monitor | Continuous health checking during testnet run | `testnet/monitor.py` |
| State persistence for tokens/pools | SQLite tables for qRC20 and AMM state | `qrdx/exchange/persistence.py`, `qrdx/tokens/persistence.py` |
| Docker multi-node compose | N-node testnet with shared network | `docker/docker-compose.testnet.yml` |
| Integration test suite | pytest-based end-to-end tests against live testnet | `tests/test_testnet_integration.py` |

---

## 4. Testnet Genesis & Chain Parameters

### 4.1 Chain Parameters

```toml
chain_id              = 9999
network_name          = "qrdx-testnet-integration"
slot_duration         = 2        # seconds
slots_per_epoch       = 8        # 16 seconds per epoch (faster for testing)
min_validators        = 1        # Allow single-validator for development
attestation_threshold = 0.667    # 2/3 + 1
```

### 4.2 Genesis Allocations

| Recipient | Type | Balance (QRDX) | Purpose |
|-----------|------|-----------------|---------|
| Validator 0 | PQ Wallet | 1,000,000 | Bootstrap validator + block proposer |
| Validator 1 | PQ Wallet | 1,000,000 | Second validator |
| Validator 2 | PQ Wallet | 1,000,000 | Third validator |
| Test User A | PQ Wallet | 500,000 | Token operations, governance |
| Test User B | Traditional Wallet | 500,000 | UTXO transfers, DEX interaction |
| Test User C | Traditional Wallet | 500,000 | Bridge simulation, multisig |
| Token Deployer | PQ Wallet | 100,000 | qRC20 token deployment gas |
| Pool Creator | PQ Wallet | 200,000 | AMM pool creation + liquidity |
| Master Controller | PQ Wallet | 0 | System wallet controller (no balance of its own) |
| System Wallets (10) | System | 75,000,000 | Protocol reserves (per constants.py) |
| Contract Test Account | Traditional | 1,000,000,000 | EVM contract deployment |

**Total genesis supply:** ~1,079,800,000 QRDX

### 4.3 Validator Stakes

Each validator stakes 100,000 QRDX at genesis (the minimum per `MIN_VALIDATOR_STAKE`).

### 4.4 Genesis Config File

The orchestrator will generate `testnet/genesis_config.json` using `qrdx.validator.genesis.GenesisCreator` with the exact same code path used by the existing `scripts/testnet.sh`. No custom genesis format — the real genesis creator is used.

---

## 5. Node Orchestration

### 5.1 Node Types

| Node | Role | Port | RPC Port | Validator | Bootstrap |
|------|------|------|----------|-----------|-----------|
| node-0 | Bootstrap + Validator | 3007 | 8545 | Yes (Validator 0) | Yes |
| node-1 | Validator | 3008 | 8546 | Yes (Validator 1) | No |
| node-2 | Validator | 3009 | 8547 | Yes (Validator 2) | No |
| node-3 | Full Node (non-validator) | 3010 | 8548 | No | No |

### 5.2 Startup Sequence

```
1. Generate all wallets (3 validator PQ + 5 test wallets)
2. Generate master controller wallet
3. Create genesis config via GenesisCreator
4. Initialize per-node SQLite databases
5. Generate per-node PQ identity keys
6. Write per-node .env configuration files
7. Start node-0 (bootstrap) — wait for /health 200
8. Start node-1 — wait for peer discovery with node-0
9. Start node-2 — wait for peer mesh (≥2 peers each)
10. Start node-3 — wait for sync to chain tip
11. Verify: all nodes at same block height
12. Verify: all validators registered and active
13. Verify: genesis balances correct on all nodes
```

### 5.3 Process Management

Each node runs as a subprocess of the orchestrator via `asyncio.create_subprocess_exec`. The orchestrator:
- Captures stdout/stderr to per-node log files
- Monitors process health via `/health` endpoint polling
- Implements graceful shutdown (SIGTERM → SIGKILL after 10s)
- Tracks PIDs for cleanup

### 5.4 Environment Variables Per Node

```bash
QRDX_NODE_HOST=127.0.0.1
QRDX_NODE_PORT=<3007+N>
QRDX_SELF_URL=http://127.0.0.1:<3007+N>
QRDX_DATABASE_PATH=testnet/databases/node<N>.db
QRDX_NODE_KEY_DIR=testnet/data/node<N>/keys
QRDX_BOOTSTRAP_NODES=http://127.0.0.1:3007
QRDX_MIN_VALIDATORS=1
QRDX_CHAIN_ID=9999
QRDX_NETWORK_NAME=qrdx-testnet-integration
QRDX_VALIDATOR_ENABLED=true|false
QRDX_VALIDATOR_WALLET=testnet/wallets/validator_<N>.json
LOG_LEVEL=DEBUG
```

---

## 6. Wallet & Funding Pipeline

### 6.1 Wallet Types Generated

| Wallet | Type | Key Algorithm | Address Format |
|--------|------|---------------|----------------|
| Validator wallets (×3) | PQ | ML-DSA-65 (Dilithium3) | `0xPQ` + 64 hex |
| Master controller | PQ | ML-DSA-65 (Dilithium3) | `0xPQ` + 64 hex |
| Test User A | PQ | ML-DSA-65 (Dilithium3) | `0xPQ` + 64 hex |
| Test User B | Traditional | secp256k1 | `0x` + 40 hex |
| Test User C | Traditional | secp256k1 | `0x` + 40 hex |
| Token Deployer | PQ | ML-DSA-65 (Dilithium3) | `0xPQ` + 64 hex |
| Pool Creator | PQ | ML-DSA-65 (Dilithium3) | `0xPQ` + 64 hex |

### 6.2 Wallet Generation Code Path

```python
# PQ Wallets — uses real liboqs, zero fallback
from qrdx.crypto.pq.dilithium import generate_keypair, PQPrivateKey
private_key, public_key = generate_keypair()  # Real ML-DSA-65

# Traditional Wallets — uses real secp256k1
from qrdx.crypto.keys import PrivateKey as ClassicalPrivateKey
private_key = ClassicalPrivateKey.generate()  # Real secp256k1
```

### 6.3 Funding Verification

After genesis, the orchestrator verifies every prefunded account by querying each node's REST API:

```
GET /get_address_info?address=<addr>
→ {"balance": "1000000", "pending_spent_outputs": [], ...}
```

All 4 nodes must return identical balances for every genesis account.

---

## 7. Transaction Engine

### 7.1 Transaction Types to Exercise

| Type | Description | Signing |
|------|-------------|---------|
| UTXO Transfer | Standard value transfer between addresses | ECDSA (P256) per existing Transaction class |
| Coinbase | Block reward to validator | Unsigned (created by block proposer) |
| System Wallet Spend | Transfer from system wallet via controller | PQ-signed by master controller |
| Validator Deposit | Stake deposit for new validator | Via validator manager |
| Validator Withdrawal | Unstake after unbonding period | Via validator manager |

### 7.2 UTXO Transaction Flow

```
1. Query sender's unspent outputs: GET /get_address_info?address=<sender>
2. Select UTXOs covering amount + fee
3. Build Transaction with inputs (tx_hash, index) and outputs (address, amount)
4. Sign with sender's private key (ECDSA P256)
5. Broadcast: POST /push_tx with hex-encoded transaction
6. Wait for inclusion: poll GET /get_transaction?tx_hash=<hash>
7. Verify on all nodes: GET /get_transaction on each node
```

### 7.3 Transaction Sender Implementation

The `testnet/tx_sender.py` module will:
- Build raw transactions from UTXOs using `qrdx.transactions.Transaction`
- Sign with the sender's private key using `qrdx.transactions.transaction_input.sign_transaction_input`
- Serialize to hex using the existing serialization pipeline
- POST to any node's `/push_tx` endpoint
- Wait for block inclusion with configurable timeout
- Verify cross-node consistency

---

## 8. Token Operations (qRC20)

### 8.1 Token Persistence (New Work Required)

The existing `qrdx/tokens/qrc20.py` QRC20Token class operates purely in-memory. For the testnet, we need state persistence. We will add:

**New file: `qrdx/tokens/persistence.py`**

```sql
CREATE TABLE IF NOT EXISTS token_registry (
    token_address TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    symbol TEXT NOT NULL,
    decimals INTEGER NOT NULL DEFAULT 18,
    total_supply TEXT NOT NULL,
    owner_address TEXT NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS token_balances (
    token_address TEXT NOT NULL,
    holder_address TEXT NOT NULL,
    balance TEXT NOT NULL DEFAULT '0',
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (token_address, holder_address)
);

CREATE TABLE IF NOT EXISTS token_allowances (
    token_address TEXT NOT NULL,
    owner_address TEXT NOT NULL,
    spender_address TEXT NOT NULL,
    allowance TEXT NOT NULL DEFAULT '0',
    PRIMARY KEY (token_address, owner_address, spender_address)
);

CREATE TABLE IF NOT EXISTS token_events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    token_address TEXT NOT NULL,
    event_type TEXT NOT NULL,
    from_address TEXT,
    to_address TEXT,
    amount TEXT,
    block_height INTEGER,
    tx_hash TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);
```

### 8.2 Token Test Scenario

```
1. Token Deployer creates "TestCoin" (TRC) with 1,000,000 supply
   → PQ-signed deployment transaction
   → Persisted to token_registry + initial balance to deployer

2. Transfer 10,000 TRC from Deployer → Test User A
   → PQ-signed transfer
   → Balance update in token_balances
   → Transfer event in token_events

3. Approve Test User B to spend 5,000 TRC from Test User A
   → PQ-signed approval
   → Allowance update in token_allowances

4. Test User B executes transferFrom(A → B, 5,000)
   → Allowance decremented, balances updated

5. Verify balances on all nodes match
```

---

## 9. Exchange & Liquidity Pools

### 9.1 Pool Persistence (New Work Required)

**New file: `qrdx/exchange/persistence.py`**

```sql
CREATE TABLE IF NOT EXISTS amm_pools (
    pool_id TEXT PRIMARY KEY,
    token_a TEXT NOT NULL,
    token_b TEXT NOT NULL,
    fee_tier INTEGER NOT NULL,
    pool_type TEXT NOT NULL DEFAULT 'STANDARD',
    sqrt_price TEXT NOT NULL,
    liquidity TEXT NOT NULL DEFAULT '0',
    tick_current INTEGER NOT NULL DEFAULT 0,
    creator_address TEXT NOT NULL,
    paused INTEGER NOT NULL DEFAULT 0,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS amm_positions (
    position_id TEXT PRIMARY KEY,
    pool_id TEXT NOT NULL,
    owner_address TEXT NOT NULL,
    tick_lower INTEGER NOT NULL,
    tick_upper INTEGER NOT NULL,
    liquidity TEXT NOT NULL,
    tokens_owed_a TEXT NOT NULL DEFAULT '0',
    tokens_owed_b TEXT NOT NULL DEFAULT '0',
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (pool_id) REFERENCES amm_pools(pool_id)
);

CREATE TABLE IF NOT EXISTS amm_swaps (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    pool_id TEXT NOT NULL,
    sender_address TEXT NOT NULL,
    token_in TEXT NOT NULL,
    token_out TEXT NOT NULL,
    amount_in TEXT NOT NULL,
    amount_out TEXT NOT NULL,
    fee_amount TEXT NOT NULL,
    sqrt_price_after TEXT NOT NULL,
    tick_after INTEGER NOT NULL,
    block_height INTEGER,
    tx_hash TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);
```

### 9.2 Pool Test Scenario

```
1. Pool Creator creates QRDX/TRC pool (0.30% fee tier, Standard type)
   → PQ-signed pool creation
   → Pool persisted to amm_pools

2. Pool Creator adds initial liquidity: 50,000 QRDX + 10,000 TRC
   → Position created in amm_positions
   → Token balances decremented

3. Test User A swaps 1,000 QRDX → TRC
   → Swap executed via AMM math (real concentrated liquidity)
   → Fee distributed: 70% LP, 15% creator, 10% treasury, 5% validators
   → Swap logged in amm_swaps

4. Test User B adds liquidity in different tick range
   → New position, pool liquidity updated

5. Verify pool state consistent across all nodes
```

---

## 10. Validator Lifecycle

### 10.1 Validator Operations to Test

| Operation | Who | Expected Result |
|-----------|-----|-----------------|
| Genesis registration | GenesisCreator | 3 validators active at epoch 0 |
| Block proposal | Selected proposer | New block every 2s with PQ signature |
| Attestation | Committee members | Signed attestations collected |
| Epoch transition | All validators | Rewards distributed, checkpoints updated |
| New validator deposit | Test User A | Activation after ACTIVATION_DELAY_EPOCHS |
| Voluntary exit | Validator 2 | Enters unbonding queue |
| Slashing (simulated) | Detector | Double-sign penalty applied |

### 10.2 Consensus Verification

```
1. Wait for 3 epochs (24 slots at 2s = 48 seconds)
2. Verify: block height ≥ 24 on all nodes
3. Verify: epoch rewards distributed to validators
4. Verify: attestation inclusion rate > 90%
5. Verify: all nodes agree on canonical chain (same block hash at each height)
```

---

## 11. P2P Network Verification

### 11.1 Checks

| Check | Method | Expected |
|-------|--------|----------|
| Peer discovery | `GET /get_nodes` on each node | Each node sees ≥ 2 peers |
| PQ identity | `GET /pq/peer_info` | ML-DSA-65 algorithm, valid @-schema |
| Node ID consistency | Compare node IDs across peer lists | BLAKE3-derived, deterministic |
| DHT routing | Query routing table via RPC | k-buckets populated |
| Block propagation | Submit block to node-0, verify on node-3 | Propagation < 5 seconds |

---

## 12. Governance Operations

### 12.1 Governance Test Scenario

```
1. Test User A creates governance proposal
   → "Reduce pool creation stake to 5,000 QRDX"
   → Deposit: 10,000,000 QRDX (from system allocation)

2. Validators vote on proposal
   → Validator 0: FOR
   → Validator 1: FOR  
   → Validator 2: AGAINST

3. Proposal passes (2/3 majority)
   → Parameter change queued with timelock

4. After timelock: parameter updated
   → EXCHANGE_POOL_STAKE_STANDARD = 5000

5. Verify new pool can be created with 5,000 QRDX stake
```

---

## 13. Bridge Operations

### 13.1 Bridge Simulation Scenario

Since we can't connect to real external chains, the bridge test simulates the QRDX-side operations:

```
1. Simulate incoming bridge deposit
   → Create shielded token (qETH) via bridge mint
   → Validator attestations on bridge event

2. Transfer qETH between users
   → Standard qRC20 transfer of shielded token

3. Simulate bridge withdrawal
   → Burn qETH via bridge burn
   → Fraud proof window starts (accelerated for testnet)

4. Verify doomsday canary is monitored
```

---

## 14. Integration Test Scenarios

### 14.1 Scenario List

Each scenario is a self-contained Python async function that runs against the live testnet.

| # | Scenario | Duration | Dependencies |
|---|----------|----------|--------------|
| 1 | **Genesis Verification** | 5s | Nodes started |
| 2 | **Peer Discovery** | 10s | Scenario 1 |
| 3 | **Block Production** | 60s | Scenario 2 |
| 4 | **UTXO Transfer** | 30s | Scenario 3 |
| 5 | **Multi-Node Consistency** | 10s | Scenario 4 |
| 6 | **qRC20 Token Deploy** | 30s | Scenario 3 |
| 7 | **qRC20 Transfer** | 30s | Scenario 6 |
| 8 | **AMM Pool Creation** | 30s | Scenario 6 |
| 9 | **AMM Swap** | 30s | Scenario 8 |
| 10 | **Validator Deposit** | 60s | Scenario 3 |
| 11 | **Epoch Rewards** | 120s | Scenario 10 |
| 12 | **System Wallet Operation** | 30s | Scenario 3 |
| 13 | **Governance Proposal** | 120s | Scenario 11 |
| 14 | **Bridge Simulation** | 60s | Scenario 6 |
| 15 | **Slashing Detection** | 60s | Scenario 11 |
| 16 | **Full Stress Test** | 300s | All prior |

### 14.2 Test Runner

```python
# testnet/run_scenarios.py
async def main():
    orchestrator = TestnetOrchestrator(config)
    
    # Phase 1: Infrastructure
    await orchestrator.start_all_nodes()
    await orchestrator.wait_for_network_ready()
    
    # Phase 2: Verification
    results = {}
    for scenario in ORDERED_SCENARIOS:
        result = await scenario.run(orchestrator)
        results[scenario.name] = result
        if result.failed and scenario.critical:
            break  # Stop on critical failure
    
    # Phase 3: Report
    orchestrator.print_report(results)
    
    # Phase 4: Cleanup
    await orchestrator.stop_all_nodes()
```

---

## 15. Docker Multi-Node Orchestration

### 15.1 Docker Compose for Testnet

**New file: `docker/docker-compose.testnet.yml`**

```yaml
services:
  testnet-genesis:
    build: ..
    command: python -m testnet.genesis_generator
    volumes:
      - testnet-shared:/testnet
    
  node-0:
    build: ..
    depends_on:
      testnet-genesis:
        condition: service_completed_successfully
    environment:
      - QRDX_NODE_PORT=3007
      - QRDX_VALIDATOR_ENABLED=true
      # ... (full env from orchestrator)
    ports:
      - "3007:3007"
      - "8545:8545"
    volumes:
      - testnet-shared:/testnet
    healthcheck:
      test: ["CMD", "python", "docker/docker-healthcheck.py"]
      interval: 5s
      timeout: 3s
      retries: 10
    networks:
      - testnet

  node-1:
    # ... similar to node-0 with QRDX_NODE_PORT=3008

  node-2:
    # ... similar with QRDX_NODE_PORT=3009

  node-3:
    # ... non-validator node

  scenario-runner:
    build: ..
    depends_on:
      node-0:
        condition: service_healthy
      node-1:
        condition: service_healthy
      node-2:
        condition: service_healthy
      node-3:
        condition: service_healthy
    command: python -m testnet.run_scenarios
    volumes:
      - testnet-shared:/testnet
    networks:
      - testnet

volumes:
  testnet-shared:

networks:
  testnet:
    driver: bridge
```

---

## 16. Monitoring & Observability

### 16.1 Health Monitor

The health monitor runs continuously during testnet operation and tracks:

| Metric | Source | Alert Threshold |
|--------|--------|-----------------|
| Block height | `GET /get_mining_info` per node | Height stall > 30s |
| Peer count | `GET /get_nodes` per node | < 2 peers |
| Block time | Timestamps between consecutive blocks | > 10s average |
| Mempool size | `GET /get_mining_info` | > 1000 pending |
| Validator active | Validator RPC | < min_validators |
| Attestation rate | Epoch processing logs | < 90% |
| Cross-node sync | Block hash comparison at same height | Divergence |
| Token balance consistency | Query same address on all nodes | Mismatch |

### 16.2 Logging

Each node writes to `testnet/logs/node-N/node.log` with structured JSON logging at DEBUG level. The orchestrator aggregates key events into `testnet/logs/orchestrator.log`.

---

## 17. Implementation Order

This is the strict order in which code will be written. Each step must pass its own verification before proceeding to the next.

### Phase 1: Persistence Layers (foundation)

| Step | Task | Files | Verification |
|------|------|-------|-------------|
| 1.1 | Token persistence (SQLite tables + CRUD) | `qrdx/tokens/persistence.py` | Unit test: create token, transfer, query balance |
| 1.2 | Exchange persistence (SQLite tables + CRUD) | `qrdx/exchange/persistence.py` | Unit test: create pool, add position, record swap |
| 1.3 | Governance persistence | `qrdx/governance/persistence.py` | Unit test: create proposal, cast vote, tally |
| 1.4 | Bridge event persistence | `qrdx/bridge/persistence.py` | Unit test: record bridge mint/burn |

### Phase 2: Testnet Infrastructure

| Step | Task | Files | Verification |
|------|------|-------|-------------|
| 2.1 | Testnet config module | `testnet/config.py` | Imports and validates |
| 2.2 | Wallet factory | `testnet/wallet_factory.py` | Generates 8 wallets, saves keystores |
| 2.3 | Genesis generator | `testnet/genesis_generator.py` | Produces valid genesis_config.json |
| 2.4 | Node orchestrator | `testnet/orchestrator.py` | Starts 4 nodes, all healthy |
| 2.5 | Health monitor | `testnet/monitor.py` | Reports block height + peer count |

### Phase 3: Transaction & Token Operations

| Step | Task | Files | Verification |
|------|------|-------|-------------|
| 3.1 | Transaction sender | `testnet/tx_sender.py` | Sends UTXO transfer, confirmed |
| 3.2 | Token deployer | `testnet/token_deployer.py` | Deploys qRC20, balance visible |
| 3.3 | Pool operator | `testnet/pool_operator.py` | Creates pool, adds liquidity, swaps |

### Phase 4: Integration Scenarios

| Step | Task | Files | Verification |
|------|------|-------|-------------|
| 4.1 | Genesis verification scenario | `testnet/scenarios/s01_genesis.py` | All balances correct |
| 4.2 | Peer discovery scenario | `testnet/scenarios/s02_peers.py` | All nodes connected |
| 4.3 | Block production scenario | `testnet/scenarios/s03_blocks.py` | Blocks advancing |
| 4.4 | UTXO transfer scenario | `testnet/scenarios/s04_transfer.py` | Tx confirmed on all nodes |
| 4.5 | Token operations scenario | `testnet/scenarios/s05_tokens.py` | Deploy + transfer verified |
| 4.6 | Exchange operations scenario | `testnet/scenarios/s06_exchange.py` | Pool + swap verified |
| 4.7 | Validator lifecycle scenario | `testnet/scenarios/s07_validators.py` | Deposit + rewards verified |
| 4.8 | System wallet scenario | `testnet/scenarios/s08_system_wallets.py` | Controller can spend |
| 4.9 | Governance scenario | `testnet/scenarios/s09_governance.py` | Proposal lifecycle |
| 4.10 | Cross-node consistency | `testnet/scenarios/s10_consistency.py` | All state matches |
| 4.11 | Stress test | `testnet/scenarios/s11_stress.py` | 100 tx burst handled |

### Phase 5: Docker & CI

| Step | Task | Files | Verification |
|------|------|-------|-------------|
| 5.1 | Docker compose testnet | `docker/docker-compose.testnet.yml` | 4 containers start |
| 5.2 | Scenario runner entry point | `testnet/run_scenarios.py` | All scenarios pass |
| 5.3 | CI integration | `.github/workflows/testnet.yml` | Green in CI |

---

## 18. File Manifest

Complete list of all files that will be created or modified:

### New Files

```
testnet/
├── __init__.py
├── config.py                    # Testnet chain parameters & paths
├── wallet_factory.py            # Generate all wallet types
├── genesis_generator.py         # Wrapper around GenesisCreator for testnet
├── orchestrator.py              # Multi-node process manager
├── monitor.py                   # Health monitoring
├── tx_sender.py                 # UTXO transaction builder + broadcaster
├── token_deployer.py            # qRC20 deployment + operations
├── pool_operator.py             # AMM pool creation + swap execution
├── rpc_client.py                # Async HTTP client for node REST/RPC APIs
├── run_scenarios.py             # Main entry point for scenario execution
├── scenarios/
│   ├── __init__.py
│   ├── base.py                  # Base scenario class
│   ├── s01_genesis.py           # Genesis balance verification
│   ├── s02_peers.py             # Peer discovery verification
│   ├── s03_blocks.py            # Block production verification
│   ├── s04_transfer.py          # UTXO transfer test
│   ├── s05_tokens.py            # qRC20 lifecycle test
│   ├── s06_exchange.py          # AMM pool + swap test
│   ├── s07_validators.py        # Validator lifecycle test
│   ├── s08_system_wallets.py    # System wallet operations
│   ├── s09_governance.py        # Governance proposal lifecycle
│   ├── s10_consistency.py       # Cross-node state consistency
│   └── s11_stress.py            # Load/stress testing

qrdx/tokens/
├── persistence.py               # SQLite persistence for qRC20 state

qrdx/exchange/
├── persistence.py               # SQLite persistence for AMM/orderbook state

qrdx/governance/
├── persistence.py               # SQLite persistence for governance state

qrdx/bridge/
├── persistence.py               # SQLite persistence for bridge events

docker/
├── docker-compose.testnet.yml   # Multi-node testnet compose

tests/
├── test_testnet_integration.py  # pytest wrapper for scenarios
```

### Modified Files

```
qrdx/database_sqlite.py          # Add new table schemas (tokens, pools, governance)
qrdx/tokens/qrc20.py             # Wire persistence hooks into state mutations
qrdx/exchange/amm.py             # Wire persistence hooks into pool operations
qrdx/exchange/state_manager.py   # Connect to SQLite persistence
qrdx/governance/proposals.py     # Wire persistence hooks
qrdx/bridge/shielding.py         # Wire persistence hooks
```

---

## 19. Success Criteria

The testnet is considered **complete and passing** when ALL of the following are true:

### Infrastructure
- [ ] 4 nodes start successfully and form a mesh network
- [ ] All nodes share identical genesis state
- [ ] PQ identity established for every node (ML-DSA-65)
- [ ] Kademlia DHT routing tables populated (≥ 2 peers per node)
- [ ] PQ handshake completed between all peer pairs

### Consensus
- [ ] Blocks produced every 2 seconds by selected proposer
- [ ] Attestations created and collected by committee members
- [ ] Epoch transitions occur every 8 slots (16 seconds)
- [ ] Rewards distributed to validators at epoch boundaries
- [ ] All nodes agree on canonical chain at every height

### Transactions
- [ ] UTXO transfer from genesis-funded wallet succeeds
- [ ] Transaction confirmed in block on all 4 nodes
- [ ] Sender UTXO consumed, receiver UTXO created
- [ ] Balance changes reflected in `GET /get_address_info`

### Tokens
- [ ] qRC20 token deployed with real PQ-signed transaction
- [ ] Token transfer between wallets succeeds
- [ ] Approval + transferFrom flow works
- [ ] Token state persisted to SQLite and survives node restart

### Exchange
- [ ] AMM pool created with real token pair
- [ ] Liquidity added with position tracking
- [ ] Swap executes with correct concentrated liquidity math
- [ ] Fees distributed per Whitepaper §7.6 split
- [ ] Pool state persisted to SQLite

### Governance
- [ ] Proposal created with deposit
- [ ] Validators cast votes
- [ ] Proposal passes/fails based on vote tally
- [ ] Parameter change applied after timelock

### System Wallets
- [ ] All 10 system wallets funded per genesis
- [ ] Master controller can authorize system wallet spend
- [ ] Non-controller cannot spend system wallet funds

### Consistency
- [ ] All 4 nodes agree on block hash at every height
- [ ] Balance queries return identical results across all nodes
- [ ] Token and pool state consistent across all nodes

### Zero Stubs
- [ ] No `mock` or `MagicMock` in any testnet code
- [ ] No `return True` bypasses in any crypto path
- [ ] No in-memory-only state (everything persisted to SQLite)
- [ ] No hardcoded block acceptance (real PoS consensus)
- [ ] All signatures use real liboqs Dilithium3 or real secp256k1/P256

---

## Appendix A: Risk Register

| Risk | Impact | Mitigation |
|------|--------|------------|
| liboqs not installed in dev container | All PQ crypto fails | Check at orchestrator startup, fail fast with clear message |
| Port conflicts with existing services | Nodes can't bind | Use dynamic port allocation with base + offset |
| SQLite WAL mode corruption under concurrent writes | Data loss | One writer per database (one node per DB file) |
| Slow block production stalls scenarios | Timeouts | Configurable timeouts with generous defaults |
| Large Dilithium signatures slow down block propagation | Network lag | Monitor propagation time, alert if > 5s |
| Genesis creator API changes | Genesis generation fails | Pin to current GenesisCreator interface |

---

## Appendix B: Glossary

| Term | Definition |
|------|-----------|
| PQ | Post-Quantum — cryptography resistant to quantum computer attacks |
| ML-DSA-65 | NIST FIPS 204 digital signature algorithm (formerly Dilithium3) |
| ML-KEM-768 | NIST FIPS 203 key encapsulation mechanism (formerly Kyber768) |
| UTXO | Unspent Transaction Output — Bitcoin-style transaction model |
| qRC20 | QRDX-native fungible token standard (ERC-20 equivalent) |
| AMM | Automated Market Maker — algorithmic liquidity pool |
| DHT | Distributed Hash Table — decentralized peer discovery |
| Epoch | 8 slots (16 seconds) — period for rewards and finality |
| Slot | 2 seconds — minimum block production interval |

---

*End of Design Document. Implementation begins after review.*
