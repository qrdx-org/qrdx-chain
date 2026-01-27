# QRDX State Integration - Visual Architecture

## Current Architecture (Broken)

```
┌─────────────────────────────────────────────────────────────────────────┐
│                         QRDX Blockchain Node                            │
├─────────────────────────────────────────────────────────────────────────┤
│                                                                         │
│   ┌──────────────────────────────────────────────────────────────┐    │
│   │                    RPC Layer (Port 3007)                     │    │
│   │  eth_sendRawTransaction, eth_call, eth_getBalance, etc.      │    │
│   └────────┬─────────────────────────────────────────────────────┘    │
│            │                                                            │
│            │ 1. Verify Signature ✅                                    │
│            │ 2. Recover Sender ✅                                      │
│            ▼                                                            │
│   ┌─────────────────────────────────────────────────────────────┐     │
│   │              EVM Executor (evm_executor_v2.py)              │     │
│   │  Runs smart contract bytecode in isolated environment       │     │
│   └────────┬────────────────────────────────────────────────────┘     │
│            │                                                            │
│            │ 3. Check Balance                                          │
│            ▼                                                            │
│   ┌─────────────────────────────────────────────────────────────┐     │
│   │        EVM State Manager (state.py)                         │     │
│   │  ┌─────────────────────────────────────────────────────┐    │     │
│   │  │  Memory Cache: _accounts_cache = {}                 │    │     │
│   │  │    "0x7E5F..." → Account(balance=0, nonce=0)  ❌   │    │     │
│   │  └─────────────────────────────────────────────────────┘    │     │
│   │  ┌─────────────────────────────────────────────────────┐    │     │
│   │  │  PostgreSQL: account_state table                    │    │     │
│   │  │    (empty - no records for QRDX addresses)  ❌     │    │     │
│   │  └─────────────────────────────────────────────────────┘    │     │
│   └─────────────────────────────────────────────────────────────┘     │
│                                                                         │
│            ❌ ERROR: Balance = 0, can't pay gas!                       │
│                                                                         │
│   ┌─────────────────────────────────────────────────────────────┐     │
│   │           QRDX Native State (database.py)                   │     │
│   │  ┌─────────────────────────────────────────────────────┐    │     │
│   │  │  PostgreSQL: unspent_outputs table                  │    │     │
│   │  │    "0x7E5F..." → 1,000,000,000 QRDX  ✅           │    │     │
│   │  └─────────────────────────────────────────────────────┘    │     │
│   │                                                              │     │
│   │  ❌ NOT CONSULTED BY EVM!                                  │     │
│   └─────────────────────────────────────────────────────────────┘     │
│                                                                         │
│   Two separate state systems with NO COMMUNICATION!                    │
│                                                                         │
└─────────────────────────────────────────────────────────────────────────┘
```

## Proposed Architecture (Fixed)

```
┌──────────────────────────────────────────────────────────────────────────┐
│                         QRDX Blockchain Node                             │
├──────────────────────────────────────────────────────────────────────────┤
│                                                                          │
│   ┌───────────────────────────────────────────────────────────────┐    │
│   │                    RPC Layer (Port 3007)                      │    │
│   │  eth_sendRawTransaction, eth_call, eth_getBalance, etc.       │    │
│   └────────┬──────────────────────────────────────────────────────┘    │
│            │                                                             │
│            │ 1. Verify Signature ✅                                     │
│            │ 2. Recover Sender ✅                                       │
│            ▼                                                             │
│   ┌───────────────────────────────────────────────────────────────┐    │
│   │          Execution Context (NEW - state_sync.py)              │    │
│   │  ┌────────────────────────────────────────────────────────┐   │    │
│   │  │  1. prepare_execution(sender):                         │   │    │
│   │  │     a. Sync balance from native → EVM                  │   │    │
│   │  │     b. Create snapshot for rollback                    │   │    │
│   │  └────────────────────────────────────────────────────────┘   │    │
│   └────────┬──────────────────────────────────────────────────────┘    │
│            │ 3. Execute with synced balance                             │
│            ▼                                                             │
│   ┌───────────────────────────────────────────────────────────────┐    │
│   │              EVM Executor (evm_executor_v2.py)                │    │
│   │  Runs smart contract bytecode                                 │    │
│   └────────┬──────────────────────────────────────────────────────┘    │
│            │                                                             │
│            │ 4. Check Balance                                           │
│            ▼                                                             │
│   ┌───────────────────────────────────────────────────────────────┐    │
│   │        EVM State Manager (state.py)                           │    │
│   │  ┌────────────────────────────────────────────────────────┐   │    │
│   │  │  Memory Cache: _accounts_cache = {}                    │   │    │
│   │  │    "0x7E5F..." → Account(                              │   │    │
│   │  │        balance=1000000000000000000000000000,  ✅       │   │    │
│   │  │        nonce=0                                         │   │    │
│   │  │    )                                                   │   │    │
│   │  └────────────────────────────────────────────────────────┘   │    │
│   │  ┌────────────────────────────────────────────────────────┐   │    │
│   │  │  PostgreSQL: account_state table                       │   │    │
│   │  │    Persisted after commit()                            │   │    │
│   │  └────────────────────────────────────────────────────────┘   │    │
│   └─────────┬───────────────────────────────────────────────────────┘  │
│             │                         ▲                                 │
│             │                         │                                 │
│             │                         │ 3. Initialize EVM account       │
│             │                         │    with synced balance          │
│             │                         │                                 │
│   ┌─────────▼─────────────────────────┴─────────────────────────────┐  │
│   │         State Sync Manager (NEW - state_sync.py)                │  │
│   │  ┌──────────────────────────────────────────────────────────┐   │  │
│   │  │  sync_address_to_evm(address, block_height):             │   │  │
│   │  │    1. Check if already synced                            │   │  │
│   │  │    2. Query native state ────────┐                       │   │  │
│   │  │    3. Convert QRDX → wei          │                       │   │  │
│   │  │    4. Update EVM account          │                       │   │  │
│   │  │    5. Record in sync registry     │                       │   │  │
│   │  └──────────────────────────────────┼───────────────────────┘   │  │
│   └─────────────────────────────────────┼───────────────────────────┘  │
│                                          │                              │
│                                          │ 2. Query: get_address_balance│
│                                          ▼                              │
│   ┌───────────────────────────────────────────────────────────────┐   │
│   │           QRDX Native State (database.py)                     │   │
│   │  ┌────────────────────────────────────────────────────────┐   │   │
│   │  │  PostgreSQL: unspent_outputs, transactions tables      │   │   │
│   │  │    "0x7E5F..." → 1,000,000,000 QRDX  ✅               │   │   │
│   │  │                                                         │   │   │
│   │  │  Master source of truth for account balances           │   │   │
│   │  └────────────────────────────────────────────────────────┘   │   │
│   └───────────────────────────────────────────────────────────────┘   │
│                                                                         │
│   ✅ States synchronized via deterministic bridge                     │
│                                                                         │
│   ┌───────────────────────────────────────────────────────────────┐   │
│   │        Sync Registry (NEW - PostgreSQL tables)                │   │
│   │  • evm_balance_sync_registry: Track synced addresses         │   │
│   │  • evm_balance_changes: Audit trail of all changes           │   │
│   │  • state_checkpoints: State roots for verification           │   │
│   └───────────────────────────────────────────────────────────────┘   │
│                                                                         │
└─────────────────────────────────────────────────────────────────────────┘
```

## Transaction Flow Comparison

### BEFORE (Broken)

```
┌─────────────────────────────────────────────────────────────────────┐
│  User Signs Transaction                                            │
│  Private Key: 0x0000...0001                                        │
│  To: Deploy Contract                                               │
│  Gas: 300000                                                       │
│  Gas Price: 20 gwei                                                │
└────────────────────────┬────────────────────────────────────────────┘
                         │
                         ▼
┌─────────────────────────────────────────────────────────────────────┐
│  RPC: eth_sendRawTransaction                                       │
│  1. Decode RLP ✅                                                  │
│  2. Extract (v, r, s) ✅                                           │
│  3. Recover public key ✅                                          │
│  4. Derive address: 0x7E5F4552091A69125d5DfCb7b8C2659029395Bdf ✅ │
│  5. Verify signature valid ✅                                      │
└────────────────────────┬────────────────────────────────────────────┘
                         │
                         ▼
┌─────────────────────────────────────────────────────────────────────┐
│  EVM Executor                                                       │
│  1. Get sender balance from EVM state                              │
│     state_manager.get_balance("0x7E5F...")                         │
│     → Returns: 0 wei ❌                                            │
│                                                                     │
│  2. Calculate gas cost                                             │
│     300000 * 20000000000 = 6,000,000,000,000,000 wei               │
│                                                                     │
│  3. Try to deduct                                                  │
│     0 - 6,000,000,000,000,000 = -6,000,000,000,000,000 ❌         │
│                                                                     │
│  4. ERROR: "Account Balance cannot be negative" ❌                 │
└─────────────────────────────────────────────────────────────────────┘

Result: Transaction REJECTED even though user has 1B QRDX!
```

### AFTER (Fixed)

```
┌─────────────────────────────────────────────────────────────────────┐
│  User Signs Transaction                                            │
│  Private Key: 0x0000...0001                                        │
│  To: Deploy Contract                                               │
│  Gas: 300000                                                       │
│  Gas Price: 20 gwei                                                │
└────────────────────────┬────────────────────────────────────────────┘
                         │
                         ▼
┌─────────────────────────────────────────────────────────────────────┐
│  RPC: eth_sendRawTransaction                                       │
│  1-5. [Same signature verification - all working ✅]               │
└────────────────────────┬────────────────────────────────────────────┘
                         │
                         ▼
┌─────────────────────────────────────────────────────────────────────┐
│  NEW: Execution Context                                            │
│  1. prepare_execution("0x7E5F...")                                 │
│                                                                     │
│  2. State Sync Manager:                                            │
│     sync_address_to_evm("0x7E5F...", block=1000)                   │
│                                                                     │
│     a. Query native state:                                         │
│        db.get_address_balance("0x7E5F...")                         │
│        → 1,000,000,000 QRDX ✅                                     │
│                                                                     │
│     b. Convert to wei:                                             │
│        1,000,000,000 * 10^18 = 1,000,000,000,000,000,000,000 wei   │
│        (1 sextillion wei = 1 billion QRDX)                         │
│                                                                     │
│     c. Initialize EVM account:                                     │
│        Account(                                                     │
│          address="0x7E5F...",                                      │
│          balance=1000000000000000000000000000,                     │
│          nonce=0                                                    │
│        )                                                            │
│                                                                     │
│     d. Record sync:                                                │
│        INSERT INTO evm_balance_sync_registry ...                   │
│                                                                     │
│  3. Create snapshot for rollback ✅                                │
└────────────────────────┬────────────────────────────────────────────┘
                         │
                         ▼
┌─────────────────────────────────────────────────────────────────────┐
│  EVM Executor                                                       │
│  1. Get sender balance from EVM state                              │
│     state_manager.get_balance("0x7E5F...")                         │
│     → Returns: 1,000,000,000,000,000,000,000,000 wei ✅            │
│                                                                     │
│  2. Calculate gas cost                                             │
│     300000 * 20000000000 = 6,000,000,000,000,000 wei               │
│                                                                     │
│  3. Deduct gas cost                                                │
│     1,000,000,000,000,000,000,000,000 - 6,000,000,000,000,000      │
│     = 999,994,000,000,000,000,000,000 wei ✅                       │
│                                                                     │
│  4. Execute contract deployment ✅                                 │
│     - Compile bytecode                                             │
│     - Initialize storage                                           │
│     - Generate contract address                                    │
│                                                                     │
│  5. SUCCESS! ✅                                                     │
└────────────────────────┬────────────────────────────────────────────┘
                         │
                         ▼
┌─────────────────────────────────────────────────────────────────────┐
│  Execution Context: finalize_execution                             │
│  1. Commit EVM state changes ✅                                    │
│  2. Record balance change in audit log ✅                          │
│  3. Return transaction hash to user ✅                             │
└─────────────────────────────────────────────────────────────────────┘

Result: Transaction SUCCEEDS! Contract deployed with proper gas payment!
```

## State Root Computation

```
                    ┌──────────────────────────────────────┐
                    │       Combined State Root            │
                    │  keccak256(native_root + evm_root)   │
                    └─────────────┬────────────────────────┘
                                  │
                 ┌────────────────┴────────────────┐
                 │                                 │
                 ▼                                 ▼
    ┌────────────────────────┐      ┌────────────────────────┐
    │  Native State Root     │      │   EVM State Root       │
    │  (UTXO Merkle Tree)    │      │  (Account Merkle Tree) │
    └────────┬───────────────┘      └────────┬───────────────┘
             │                                │
             │                                │
    ┌────────▼────────────┐          ┌───────▼────────────┐
    │  UTXO Set           │          │  Account Trie      │
    ├─────────────────────┤          ├────────────────────┤
    │ tx1:0 → 100 QRDX    │          │ 0x7E5F... →       │
    │ tx2:1 → 500 QRDX    │          │   balance: 10^27   │
    │ tx3:0 → 250 QRDX    │          │   nonce: 0         │
    │ ...                 │          │                    │
    └─────────────────────┘          │ 0xABCD... →       │
                                     │   balance: 10^24   │
                                     │   nonce: 5         │
                                     │   code: 0x6080...  │
                                     │ ...                │
                                     └────────────────────┘

All validators MUST compute identical state roots.
This proves consensus on both native and EVM state.
```

## Key Conversion Formula

```
┌──────────────────────────────────────────────────────────────────────┐
│                   QRDX ←→ Wei Conversion                            │
├──────────────────────────────────────────────────────────────────────┤
│                                                                      │
│  Constant: WEI_PER_QRDX = 10^18 (1 quintillion)                     │
│  (Same as Ethereum: 1 ETH = 10^18 wei)                              │
│                                                                      │
│  ┌────────────────────────────────────────────────────────────────┐ │
│  │  QRDX → Wei                                                    │ │
│  │                                                                │ │
│  │  wei = int(qrdx * Decimal(10**18))                            │ │
│  │                                                                │ │
│  │  Examples:                                                     │ │
│  │    1 QRDX     → 1,000,000,000,000,000,000 wei                 │ │
│  │    0.5 QRDX   → 500,000,000,000,000,000 wei                   │ │
│  │    1000 QRDX  → 1,000,000,000,000,000,000,000 wei             │ │
│  │    1B QRDX    → 1,000,000,000,000,000,000,000,000,000 wei     │ │
│  └────────────────────────────────────────────────────────────────┘ │
│                                                                      │
│  ┌────────────────────────────────────────────────────────────────┐ │
│  │  Wei → QRDX                                                    │ │
│  │                                                                │ │
│  │  qrdx = Decimal(wei) / Decimal(10**18)                        │ │
│  │                                                                │ │
│  │  Examples:                                                     │ │
│  │    1,000,000,000,000,000,000 wei → 1 QRDX                     │ │
│  │    500,000,000,000,000,000 wei   → 0.5 QRDX                   │ │
│  │    1 wei                          → 0.000000000000000001 QRDX  │ │
│  └────────────────────────────────────────────────────────────────┘ │
│                                                                      │
│  Important:                                                          │
│  • Always use int for wei (no decimals)                             │
│  • Always use Decimal for QRDX (precision required)                 │
│  • Conversion is deterministic (same on all nodes)                  │
│                                                                      │
└──────────────────────────────────────────────────────────────────────┘
```

## Database Tables

### New Tables Required

```sql
-- 1. Sync Registry
evm_balance_sync_registry
├── address (PK)                  -- "0x7E5F4552..."
├── last_sync_block_height        -- 1000
├── last_sync_block_hash          -- "0xabc123..."
├── last_sync_timestamp           -- 2025-01-20 15:30:00
├── native_balance_at_sync        -- 1000000000 (QRDX)
└── evm_balance_at_sync           -- 1000000000000000000000000000 (wei)

Purpose: Track which addresses have been synced and when
Queries: Fast lookup to check if address needs resync

-- 2. Balance Changes
evm_balance_changes
├── change_id (PK)                -- Auto-increment
├── address                       -- "0x7E5F4552..."
├── block_height                  -- 1001
├── block_hash                    -- "0xdef456..."
├── tx_hash                       -- "0x789abc..."
├── balance_before                -- 1000000000000000000000000000
├── balance_after                 -- 999994000000000000000000000
├── delta                         -- -6000000000000000
├── change_reason                 -- "gas_payment"
└── changed_at                    -- 2025-01-20 15:31:00

Purpose: Audit trail of ALL balance changes
Queries: Track account history, verify state transitions

-- 3. State Checkpoints
state_checkpoints
├── checkpoint_id (PK)            -- Auto-increment
├── block_height                  -- 1000
├── block_hash                    -- "0xabc123..."
├── native_state_root             -- "0x111..."
├── evm_state_root                -- "0x222..."
├── combined_state_root           -- "0x333..."
├── total_synced_addresses        -- 42
├── total_native_balance          -- 100000000 (QRDX)
├── total_evm_balance             -- 100000000000000000000000000 (wei)
└── checkpointed_at               -- 2025-01-20 15:30:00

Purpose: Verify state roots, detect consensus issues
Queries: Check if all validators agree on state
```

## Security Guarantees

```
┌───────────────────────────────────────────────────────────────────┐
│                     Security Properties                           │
├───────────────────────────────────────────────────────────────────┤
│                                                                   │
│  ✅ Deterministic                                                │
│     • All nodes sync same balances at same block height          │
│     • Conversion formula is constant (10^18 wei per QRDX)        │
│     • No timestamps except block header (deterministic)          │
│     • No random numbers                                          │
│     • No external APIs                                           │
│                                                                   │
│  ✅ Consensus-Safe                                               │
│     • Sync happens BEFORE execution (same order all nodes)       │
│     • State roots computed identically                           │
│     • Validators can verify each other's state                   │
│     • Forks handled correctly (state checkpoints)                │
│                                                                   │
│  ✅ Atomic                                                        │
│     • PostgreSQL transactions wrap sync + execution              │
│     • EVM snapshots enable rollback                              │
│     • Failed tx reverts BOTH native and EVM state                │
│     • No partial state updates                                   │
│                                                                   │
│  ✅ Auditable                                                     │
│     • Every sync logged in registry                              │
│     • Every balance change logged                                │
│     • State roots at every checkpoint                            │
│     • Complete history preserved                                 │
│                                                                   │
│  ✅ No Double-Spending                                            │
│     • Balance exists in one place at a time                      │
│     • Sync is one-way: native → EVM                              │
│     • (Future: lock mechanism for bidirectional)                 │
│     • Cannot create or destroy money                             │
│                                                                   │
└───────────────────────────────────────────────────────────────────┘
```

---

**Document Purpose**: Visual reference for state integration architecture
**Audience**: Developers implementing the solution
**Related Docs**: 
- [`CONTRACT_STATE_INTEGRATION.md`](CONTRACT_STATE_INTEGRATION.md) - High-level design
- [`STATE_BRIDGE_IMPLEMENTATION.md`](STATE_BRIDGE_IMPLEMENTATION.md) - Implementation details
- [`STATE_INTEGRATION_SUMMARY.md`](STATE_INTEGRATION_SUMMARY.md) - Executive summary
