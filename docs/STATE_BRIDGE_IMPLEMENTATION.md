# State Bridge Implementation - Detailed Technical Specification

## Overview

This document provides the complete technical specification for implementing a state bridge between QRDX's native UTXO-based chain state and the EVM's account-based contract state.

## Problem Statement

### Current Architecture - Two Isolated State Systems

#### System 1: QRDX Native State (UTXO Model)
**Location**: `qrdx/database.py`
- **Storage**: PostgreSQL tables (`transactions`, `unspent_outputs`, `blocks`)
- **Model**: UTXO (Unspent Transaction Output) based
- **Balance Query**: `async def get_address_balance(address: str) -> Decimal`
- **Unit**: QRDX tokens (with decimal precision)
- **Genesis Funding**: Via `pre_allocations` in `GenesisConfig`

```python
# Example: Test account in genesis
config.pre_allocations["0x7E5F4552091A69125d5DfCb7b8C2659029395Bdf"] = Decimal("1000000000")
# Result: Account has 1B QRDX in native state ✅
```

#### System 2: EVM Contract State (Account Model)
**Location**: `qrdx/contracts/state.py`
- **Storage**: PostgreSQL table (`account_state`) + in-memory cache (`_accounts_cache`)
- **Model**: Ethereum account-based (balance, nonce, code, storage)
- **Balance Query**: `async def get_balance(address: str) -> int`
- **Unit**: wei (smallest Ethereum unit, 1 ETH = 10^18 wei)
- **Initialization**: Empty for all addresses

```python
# Same account queried from EVM state
evm_balance = await state_manager.get_balance("0x7E5F4552...")
# Result: 0 wei (not found in EVM state) ❌
```

### The Disconnect

```
┌──────────────────────────────────────────────────────────────┐
│                    Contract Transaction Flow                  │
├──────────────────────────────────────────────────────────────┤
│                                                              │
│  1. User signs transaction with private key                 │
│     ✅ Signature: valid ECDSA                               │
│                                                              │
│  2. RPC receives eth_sendRawTransaction                     │
│     ✅ Recovers sender: 0x7E5F4552...                       │
│                                                              │
│  3. Check QRDX native balance                               │
│     ✅ Database.get_address_balance() → 1B QRDX            │
│     [NOT CHECKED - EVM doesn't query this!]                 │
│                                                              │
│  4. EVM executor checks balance                             │
│     ❌ ContractStateManager.get_balance() → 0 wei          │
│                                                              │
│  5. Try to deduct gas cost                                  │
│     ❌ 0 - 64737000000000 = NEGATIVE ❌                    │
│                                                              │
│  6. Transaction fails                                       │
│     Error: "Account Balance cannot be negative"             │
│                                                              │
└──────────────────────────────────────────────────────────────┘
```

## Why These Systems Are Separate

### Historical Context
1. **QRDX Chain**: Originally designed as a UTXO-based cryptocurrency (similar to Bitcoin)
2. **EVM Integration**: Added later to support smart contracts (Ethereum compatibility)
3. **Different Models**: UTXO vs Account-based state require fundamentally different storage

### Technical Reasons
- **UTXO Model**: Privacy-preserving, parallelizable, no account state
- **Account Model**: Required for Ethereum compatibility, contract interactions
- **Performance**: Separate indexes optimized for different query patterns
- **Modularity**: EVM can be upgraded without touching core chain

### Why They Weren't Connected
The integration was incomplete - the EVM execution layer was added but never bridged to the native chain state.

## Security Requirements for Proper Integration

### 1. Deterministic State Transitions
**Requirement**: All nodes must compute identical state given the same inputs.

**Implications**:
- No randomness (timestamps must be from block headers)
- No external data sources
- All operations must be pure functions
- Order of operations must be deterministic

**Code Example**:
```python
# ❌ BAD - Non-deterministic (uses system time)
timestamp = time.time()

# ✅ GOOD - Deterministic (uses block timestamp)
timestamp = block.timestamp
```

### 2. Consensus Safety
**Requirement**: All validators must agree on state at each block height.

**Implications**:
- State sync must happen at block boundaries
- No async state updates outside consensus
- Rollbacks must be atomic across both states
- Forks must handle state correctly

**Critical Points**:
```python
# State sync must happen BEFORE block execution
# All nodes execute in same order:
# 1. Sync balances from native → EVM
# 2. Execute all contract transactions  
# 3. Commit both states atomically
# 4. Include state roots in block header
```

### 3. Atomic State Updates
**Requirement**: Either both states update or neither updates.

**Implications**:
- Database transactions must span both states
- Rollback capability required
- State snapshots before risky operations
- Two-phase commit pattern

**Code Pattern**:
```python
async with db.transaction():  # Begin atomic transaction
    # Phase 1: Prepare
    await sync_balance_to_evm(address)
    evm_state.snapshot()
    
    try:
        # Phase 2: Execute
        result = await execute_contract(...)
        
        if result.success:
            # Phase 3: Commit both
            await evm_state.commit()
            await update_native_state(...)
        else:
            # Rollback both
            await evm_state.revert()
            # DB transaction will auto-rollback
    except Exception:
        await evm_state.revert()
        raise  # DB transaction will auto-rollback
```

### 4. Double-Spend Prevention
**Requirement**: Tokens can only exist in one state at a time.

**Implications**:
- Moving QRDX → EVM must "lock" or "burn" native tokens
- Moving EVM → QRDX must "unlock" or "mint" native tokens
- Locks must be verifiable by all nodes
- No way to access locked tokens from native side

**State Machine**:
```
QRDX Native State:
  [1B QRDX available] --lock--> [1B QRDX locked] --unlock--> [1B QRDX available]
                                        ↓                         ↑
                                      bridge                   bridge
                                        ↓                         ↑
EVM State:
  [0 wei] ------------------mint--> [10^27 wei] --burn--> [0 wei]

INVARIANT: native_available + (evm_balance / 10^18) = total_original_balance
```

### 5. Cryptographic Verification
**Requirement**: All state changes must be verifiable.

**Implications**:
- State roots computed via Merkle trees
- Lock/unlock proofs cryptographically signed
- All nodes can verify state transitions independently
- No trusted parties

**Merkle Tree Structure**:
```
                        Combined State Root
                        /                 \
              Native State Root       EVM State Root
              /             \          /           \
        UTXO Tree      Balance Tree   Account Tree  Storage Tree
```

## Proposed Solution: Lazy Balance Synchronization

### Design Philosophy

Instead of:
- ❌ Duplicating all balances in both systems (expensive, complex)
- ❌ Replacing UTXO model with accounts (breaks existing chain)
- ❌ Creating centralized oracle (not decentralized)

We implement:
- ✅ **Lazy sync**: Copy balance to EVM only when needed
- ✅ **One-way at first**: Native → EVM (for gas payments)
- ✅ **Cache with invalidation**: Fast subsequent accesses
- ✅ **Block-level consistency**: Sync at deterministic points

### Architecture

```
┌────────────────────────────────────────────────────────────────────┐
│                       QRDX Unified State Layer                     │
├────────────────────────────────────────────────────────────────────┤
│                                                                    │
│  ┌──────────────────────────┐                                     │
│  │  Transaction Received     │                                     │
│  │  (signed, verified)       │                                     │
│  └──────────┬────────────────┘                                     │
│             │                                                       │
│             ▼                                                       │
│  ┌──────────────────────────┐                                     │
│  │  State Sync Manager      │                                     │
│  ├──────────────────────────┤                                     │
│  │ 1. Check if EVM has      │                                     │
│  │    sender's balance      │                                     │
│  │ 2. If not, query native  │                                     │
│  │    state                 │                                     │
│  │ 3. Convert QRDX → wei    │                                     │
│  │ 4. Initialize EVM account│                                     │
│  │ 5. Mark as synced        │                                     │
│  └──────────┬────────────────┘                                     │
│             │                                                       │
│             ▼                                                       │
│  ┌──────────────────────────┐    ┌──────────────────────────┐    │
│  │  Native State (UTXO)     │◄───┤  EVM State (Accounts)   │    │
│  ├──────────────────────────┤    ├──────────────────────────┤    │
│  │ • Original balances      │    │ • Synced balances        │    │
│  │ • UTXO set               │    │ • Contract code          │    │
│  │ • Transaction history    │    │ • Contract storage       │    │
│  │ • Master source of truth │    │ • Execution state        │    │
│  └──────────────────────────┘    └──────────────────────────┘    │
│             │                                   │                  │
│             │         ┌──────────────────┐     │                  │
│             └────────►│  Sync Registry   │◄────┘                  │
│                       ├──────────────────┤                        │
│                       │ Tracks which     │                        │
│                       │ addresses have   │                        │
│                       │ been synced and  │                        │
│                       │ at what block    │                        │
│                       └──────────────────┘                        │
│                                                                    │
└────────────────────────────────────────────────────────────────────┘
```

### Implementation Components

## 1. Database Schema for Sync Registry

```sql
-- Track which addresses have been synced to EVM state
CREATE TABLE IF NOT EXISTS evm_balance_sync_registry (
    address TEXT PRIMARY KEY,
    
    -- When was this address last synced?
    last_sync_block_height INTEGER NOT NULL,
    last_sync_block_hash CHAR(64) NOT NULL,
    last_sync_timestamp TIMESTAMP NOT NULL DEFAULT NOW(),
    
    -- What was synced?
    native_balance_at_sync NUMERIC(20, 8) NOT NULL,  -- QRDX units
    evm_balance_at_sync BIGINT NOT NULL,              -- wei units
    
    -- Verification
    sync_tx_hash CHAR(64),  -- Transaction that triggered sync (if any)
    merkle_proof TEXT,       -- Optional: proof of sync
    
    -- Indexes
    INDEX idx_sync_block_height (last_sync_block_height),
    INDEX idx_sync_timestamp (last_sync_timestamp)
);

-- Track balance changes from contract execution
CREATE TABLE IF NOT EXISTS evm_balance_changes (
    change_id SERIAL PRIMARY KEY,
    
    -- What changed?
    address TEXT NOT NULL,
    block_height INTEGER NOT NULL,
    block_hash CHAR(64) NOT NULL,
    tx_hash CHAR(64) NOT NULL,
    
    -- Change details
    balance_before BIGINT NOT NULL,
    balance_after BIGINT NOT NULL,
    delta BIGINT NOT NULL,  -- Can be negative
    
    -- Why did it change?
    change_reason TEXT NOT NULL,  -- 'gas_payment', 'contract_call', 'value_transfer'
    
    -- Timestamp
    changed_at TIMESTAMP NOT NULL DEFAULT NOW(),
    
    -- Indexes
    INDEX idx_address (address),
    INDEX idx_block_height (block_height),
    INDEX idx_tx_hash (tx_hash)
);

-- Checkpoint state roots for verification
CREATE TABLE IF NOT EXISTS state_checkpoints (
    checkpoint_id SERIAL PRIMARY KEY,
    
    block_height INTEGER NOT NULL UNIQUE,
    block_hash CHAR(64) NOT NULL,
    
    -- State roots
    native_state_root CHAR(64) NOT NULL,
    evm_state_root CHAR(64) NOT NULL,
    combined_state_root CHAR(64) NOT NULL,
    
    -- Statistics
    total_synced_addresses INTEGER NOT NULL,
    total_native_balance NUMERIC(20, 8) NOT NULL,
    total_evm_balance BIGINT NOT NULL,
    
    checkpointed_at TIMESTAMP NOT NULL DEFAULT NOW(),
    
    INDEX idx_block_height (block_height)
);
```

## 2. State Sync Manager Implementation

**File**: `qrdx/contracts/state_sync.py`

```python
"""
State Synchronization Manager

Bridges QRDX native state (UTXO) with EVM contract state (accounts).
Ensures all nodes see consistent state by syncing at deterministic points.
"""

from typing import Optional
from decimal import Decimal
from eth_utils import to_checksum_address
import asyncio

from ..logger import get_logger
from ..database import Database
from .state import ContractStateManager, Account

logger = get_logger(__name__)

# Conversion constants
WEI_PER_QRDX = 10**18  # 1 QRDX = 10^18 wei (Ethereum standard)


class StateSyncManager:
    """
    Manages synchronization between QRDX native state and EVM state.
    
    This is a CONSENSUS-CRITICAL component. All operations must be:
    - Deterministic (same input → same output on all nodes)
    - Atomic (all or nothing)
    - Verifiable (provable by cryptographic means)
    """
    
    def __init__(
        self,
        db: Database,
        evm_state: ContractStateManager
    ):
        """
        Initialize state sync manager.
        
        Args:
            db: Native chain database
            evm_state: EVM state manager
        """
        self.db = db
        self.evm_state = evm_state
        
    async def sync_address_to_evm(
        self,
        address: str,
        block_height: int,
        block_hash: str,
        force: bool = False
    ) -> bool:
        """
        Synchronize an address's balance from native state to EVM state.
        
        This is called before executing any contract transaction to ensure
        the sender has their balance available in EVM state.
        
        Args:
            address: Address to sync (must be checksummed)
            block_height: Current block height (for determinism)
            block_hash: Current block hash (for verification)
            force: If True, sync even if already synced recently
            
        Returns:
            True if sync performed, False if skipped (already synced)
        """
        address = to_checksum_address(address)
        
        # Check if already synced at this block height
        if not force:
            already_synced = await self._is_already_synced(
                address,
                block_height
            )
            if already_synced:
                logger.debug(
                    f"Address {address} already synced at block {block_height}"
                )
                return False
        
        # Get native balance (source of truth)
        native_balance_qrdx = await self.db.get_address_balance(address)
        
        # Convert to wei (EVM units)
        # 1 QRDX = 10^18 wei
        native_balance_wei = int(native_balance_qrdx * Decimal(WEI_PER_QRDX))
        
        # Get current EVM balance
        current_evm_balance = await self.evm_state.get_balance(address)
        
        # Initialize or update EVM account
        account = await self.evm_state.get_account(address)
        account.balance = native_balance_wei
        await self.evm_state.set_account(account)
        
        # Record sync in registry
        await self._record_sync(
            address=address,
            block_height=block_height,
            block_hash=block_hash,
            native_balance=native_balance_qrdx,
            evm_balance=native_balance_wei
        )
        
        logger.info(
            f"Synced address {address}: "
            f"{native_balance_qrdx} QRDX → {native_balance_wei} wei "
            f"at block {block_height}"
        )
        
        return True
    
    async def _is_already_synced(
        self,
        address: str,
        block_height: int
    ) -> bool:
        """
        Check if address was already synced at or after given block.
        
        Args:
            address: Address to check
            block_height: Block height to check against
            
        Returns:
            True if already synced
        """
        async with self.db.pool.acquire() as conn:
            row = await conn.fetchrow(
                """
                SELECT last_sync_block_height
                FROM evm_balance_sync_registry
                WHERE address = $1
                AND last_sync_block_height >= $2
                """,
                address,
                block_height
            )
        
        return row is not None
    
    async def _record_sync(
        self,
        address: str,
        block_height: int,
        block_hash: str,
        native_balance: Decimal,
        evm_balance: int
    ) -> None:
        """
        Record sync in registry.
        
        Args:
            address: Address that was synced
            block_height: Block height at sync
            block_hash: Block hash at sync
            native_balance: Native balance in QRDX
            evm_balance: EVM balance in wei
        """
        async with self.db.pool.acquire() as conn:
            await conn.execute(
                """
                INSERT INTO evm_balance_sync_registry (
                    address,
                    last_sync_block_height,
                    last_sync_block_hash,
                    native_balance_at_sync,
                    evm_balance_at_sync
                )
                VALUES ($1, $2, $3, $4, $5)
                ON CONFLICT (address) DO UPDATE SET
                    last_sync_block_height = EXCLUDED.last_sync_block_height,
                    last_sync_block_hash = EXCLUDED.last_sync_block_hash,
                    last_sync_timestamp = NOW(),
                    native_balance_at_sync = EXCLUDED.native_balance_at_sync,
                    evm_balance_at_sync = EXCLUDED.evm_balance_at_sync
                """,
                address,
                block_height,
                block_hash,
                str(native_balance),
                evm_balance
            )
    
    async def record_balance_change(
        self,
        address: str,
        block_height: int,
        block_hash: str,
        tx_hash: str,
        balance_before: int,
        balance_after: int,
        reason: str
    ) -> None:
        """
        Record a balance change from contract execution.
        
        This provides an audit trail of all balance changes.
        
        Args:
            address: Address whose balance changed
            block_height: Block height of change
            block_hash: Block hash
            tx_hash: Transaction that caused change
            balance_before: Balance before (wei)
            balance_after: Balance after (wei)
            reason: Why balance changed
        """
        delta = balance_after - balance_before
        
        async with self.db.pool.acquire() as conn:
            await conn.execute(
                """
                INSERT INTO evm_balance_changes (
                    address,
                    block_height,
                    block_hash,
                    tx_hash,
                    balance_before,
                    balance_after,
                    delta,
                    change_reason
                )
                VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
                """,
                address,
                block_height,
                block_hash,
                tx_hash,
                balance_before,
                balance_after,
                delta,
                reason
            )
    
    async def create_state_checkpoint(
        self,
        block_height: int,
        block_hash: str
    ) -> str:
        """
        Create a state checkpoint at block boundary.
        
        Computes combined state root from both native and EVM state.
        All nodes must compute identical root.
        
        Args:
            block_height: Block height to checkpoint
            block_hash: Block hash
            
        Returns:
            Combined state root
        """
        # Get native state root (from UTXO set)
        native_root = await self._compute_native_state_root(block_height)
        
        # Get EVM state root (from account trie)
        evm_root = await self.evm_state.get_state_root()
        
        # Combine roots deterministically
        # keccak256(native_root + evm_root)
        from eth_utils import keccak
        combined_root = keccak(
            bytes.fromhex(native_root) +
            bytes.fromhex(evm_root)
        ).hex()
        
        # Get statistics
        stats = await self._get_sync_statistics()
        
        # Store checkpoint
        async with self.db.pool.acquire() as conn:
            await conn.execute(
                """
                INSERT INTO state_checkpoints (
                    block_height,
                    block_hash,
                    native_state_root,
                    evm_state_root,
                    combined_state_root,
                    total_synced_addresses,
                    total_native_balance,
                    total_evm_balance
                )
                VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
                """,
                block_height,
                block_hash,
                native_root,
                evm_root,
                combined_root,
                stats['synced_count'],
                str(stats['native_total']),
                stats['evm_total']
            )
        
        logger.info(
            f"State checkpoint at block {block_height}: "
            f"combined_root={combined_root[:16]}..."
        )
        
        return combined_root
    
    async def _compute_native_state_root(self, block_height: int) -> str:
        """
        Compute Merkle root of native UTXO state.
        
        Args:
            block_height: Block height to compute for
            
        Returns:
            State root (hex)
        """
        # Get all UTXOs at this block height
        async with self.db.pool.acquire() as conn:
            utxos = await conn.fetch(
                """
                SELECT tx_hash, index, amount, address
                FROM unspent_outputs uo
                INNER JOIN transactions t ON uo.tx_hash = t.tx_hash
                INNER JOIN blocks b ON t.block_hash = b.hash
                WHERE b.id <= $1
                ORDER BY tx_hash, index
                """,
                block_height
            )
        
        # Build Merkle tree from UTXOs
        from eth_utils import keccak
        
        if not utxos:
            return '0' * 64  # Empty state
        
        # Leaf nodes: keccak256(tx_hash + index + amount + address)
        leaves = []
        for utxo in utxos:
            leaf_data = (
                bytes.fromhex(utxo['tx_hash']) +
                utxo['index'].to_bytes(4, 'big') +
                int(utxo['amount']).to_bytes(32, 'big') +
                utxo['address'].encode('utf-8')
            )
            leaves.append(keccak(leaf_data))
        
        # Build tree
        current_level = leaves
        while len(current_level) > 1:
            next_level = []
            for i in range(0, len(current_level), 2):
                if i + 1 < len(current_level):
                    combined = keccak(current_level[i] + current_level[i + 1])
                else:
                    combined = current_level[i]  # Odd node promoted
                next_level.append(combined)
            current_level = next_level
        
        return current_level[0].hex()
    
    async def _get_sync_statistics(self) -> dict:
        """
        Get synchronization statistics.
        
        Returns:
            Dictionary with sync stats
        """
        async with self.db.pool.acquire() as conn:
            row = await conn.fetchrow(
                """
                SELECT
                    COUNT(*) as synced_count,
                    SUM(native_balance_at_sync) as native_total,
                    SUM(evm_balance_at_sync) as evm_total
                FROM evm_balance_sync_registry
                """
            )
        
        return {
            'synced_count': row['synced_count'] or 0,
            'native_total': Decimal(row['native_total'] or 0),
            'evm_total': int(row['evm_total'] or 0)
        }


class ExecutionContext:
    """
    Execution context for contract transactions.
    
    Combines native state, EVM state, and sync manager to provide
    unified execution environment.
    """
    
    def __init__(
        self,
        block_height: int,
        block_hash: str,
        block_timestamp: int,
        db: Database,
        evm_state: ContractStateManager,
        sync_manager: StateSyncManager
    ):
        """
        Initialize execution context.
        
        Args:
            block_height: Current block height
            block_hash: Current block hash
            block_timestamp: Block timestamp (deterministic!)
            db: Native chain database
            evm_state: EVM state manager
            sync_manager: State sync manager
        """
        self.block_height = block_height
        self.block_hash = block_hash
        self.block_timestamp = block_timestamp
        self.db = db
        self.evm_state = evm_state
        self.sync_manager = sync_manager
        
        # State snapshots for rollback
        self._evm_snapshot_id = None
    
    async def prepare_execution(self, sender: str) -> None:
        """
        Prepare execution environment for sender.
        
        1. Sync sender's balance from native to EVM
        2. Create state snapshot for potential rollback
        
        Args:
            sender: Sender address
        """
        # Sync balance (this is deterministic - all nodes do same)
        await self.sync_manager.sync_address_to_evm(
            address=sender,
            block_height=self.block_height,
            block_hash=self.block_hash
        )
        
        # Create snapshot
        self._evm_snapshot_id = await self.evm_state.snapshot()
        
        logger.debug(
            f"Prepared execution for {sender} at block {self.block_height}"
        )
    
    async def finalize_execution(
        self,
        sender: str,
        tx_hash: str,
        success: bool,
        gas_used: int,
        gas_price: int,
        value: int
    ) -> None:
        """
        Finalize execution and update state.
        
        Args:
            sender: Sender address
            tx_hash: Transaction hash
            success: Whether execution succeeded
            gas_used: Gas consumed
            gas_price: Gas price
            value: Value transferred
        """
        if success:
            # Commit EVM state
            await self.evm_state.commit(self._evm_snapshot_id)
            
            # Record balance change
            balance_after = await self.evm_state.get_balance(sender)
            gas_cost = gas_used * gas_price
            balance_before = balance_after + gas_cost + value
            
            await self.sync_manager.record_balance_change(
                address=sender,
                block_height=self.block_height,
                block_hash=self.block_hash,
                tx_hash=tx_hash,
                balance_before=balance_before,
                balance_after=balance_after,
                reason='gas_payment'
            )
            
            logger.info(
                f"Finalized successful execution: "
                f"tx={tx_hash[:16]}... gas_used={gas_used}"
            )
        else:
            # Revert EVM state
            await self.evm_state.revert(self._evm_snapshot_id)
            
            logger.info(
                f"Reverted failed execution: tx={tx_hash[:16]}..."
            )
```

## 3. RPC Handler Integration

**File**: Update `qrdx/node/main.py`

```python
# Around line 2000 where RPC handlers are defined

async def eth_sendRawTransaction_handler(raw_tx_hex):
    """
    Send a pre-signed raw transaction with full state integration.
    
    This handler:
    1. Verifies signature (already implemented)
    2. Syncs sender balance from native to EVM
    3. Executes in EVM with proper state management
    4. Records changes and checkpoints
    """
    try:
        # ... existing signature verification code ...
        # (Lines 2087-2138 stay the same)
        
        # Get current block for determinism
        current_block = await db.get_last_block()
        block_height = current_block.block_height
        block_hash = current_block.block_hash
        block_timestamp = current_block.timestamp
        
        # Create sync manager
        sync_manager = StateSyncManager(
            db=db,
            evm_state=state_manager
        )
        
        # Create execution context
        context = ExecutionContext(
            block_height=block_height,
            block_hash=block_hash,
            block_timestamp=block_timestamp,
            db=db,
            evm_state=state_manager,
            sync_manager=sync_manager
        )
        
        # Prepare (sync balance)
        sender_addr = encode_hex(sender)
        await context.prepare_execution(sender_addr)
        
        # Generate transaction hash (for logging)
        tx_hash = keccak(raw_tx).hex()
        
        # Execute contract
        try:
            result = evm_executor.execute(
                sender=sender,
                to=to_bytes if to_bytes else None,
                value=value_wei,
                data=data,
                gas=gas,
                gas_price=gas_price_wei
            )
            
            # Finalize (commit or revert)
            await context.finalize_execution(
                sender=sender_addr,
                tx_hash=tx_hash,
                success=result.success,
                gas_used=result.gas_used,
                gas_price=gas_price_wei,
                value=value_wei
            )
            
            if not result.success:
                return {
                    "jsonrpc": "2.0",
                    "id": None,
                    "error": {
                        "code": -32000,
                        "message": f"Execution failed: {result.error}"
                    }
                }
            
            # Return transaction hash
            return {
                "jsonrpc": "2.0",
                "id": None,
                "result": f"0x{tx_hash}"
            }
            
        except Exception as e:
            # Always revert on exception
            await context.finalize_execution(
                sender=sender_addr,
                tx_hash=tx_hash,
                success=False,
                gas_used=0,
                gas_price=0,
                value=0
            )
            raise
            
    except Exception as e:
        logger.error(f"Error in eth_sendRawTransaction: {e}", exc_info=True)
        return {
            "jsonrpc": "2.0",
            "id": None,
            "error": {
                "code": -32000,
                "message": str(e)
            }
        }
```

## 4. Validator Integration

**File**: Update `qrdx/validator/manager.py` - Block Proposal

```python
# In ValidatorManager class, update _execute_contract_transactions method
# Around line 940

async def _execute_contract_transactions(
    self,
    transactions: List,
    parent_state_root: str,
    block_height: int,
    block_hash: str,
    block_timestamp: int
) -> Tuple[List[dict], str]:
    """
    Execute contract transactions for block proposal.
    
    NOW WITH STATE SYNC!
    """
    logger.info(
        f"Executing {len(transactions)} contract transactions "
        f"for block {block_height}"
    )
    
    # Create sync manager
    sync_manager = StateSyncManager(
        db=self.db,
        evm_state=self.state_manager
    )
    
    receipts = []
    
    for tx in transactions:
        try:
            # Create execution context
            context = ExecutionContext(
                block_height=block_height,
                block_hash=block_hash,
                block_timestamp=block_timestamp,
                db=self.db,
                evm_state=self.state_manager,
                sync_manager=sync_manager
            )
            
            # Extract sender from signature
            # (This code already exists in eth_sendRawTransaction)
            sender = recover_sender_from_tx(tx)  # Implement this helper
            
            # Prepare (sync balance)
            await context.prepare_execution(sender)
            
            # Execute
            result = self.evm_executor.execute(...)
            
            # Finalize
            await context.finalize_execution(
                sender=sender,
                tx_hash=tx['hash'],
                success=result.success,
                gas_used=result.gas_used,
                gas_price=tx['gasPrice'],
                value=tx.get('value', 0)
            )
            
            # Add receipt
            receipts.append({
                'transactionHash': tx['hash'],
                'status': 1 if result.success else 0,
                'gasUsed': result.gas_used,
                ...
            })
            
        except Exception as e:
            logger.error(
                f"Contract execution failed: {e}",
                exc_info=True
            )
            receipts.append({
                'transactionHash': tx.get('hash', 'unknown'),
                'status': 0,
                'error': str(e)
            })
    
    # Create state checkpoint after all executions
    new_state_root = await sync_manager.create_state_checkpoint(
        block_height=block_height,
        block_hash=block_hash
    )
    
    logger.info(
        f"Executed {len(receipts)} transactions, "
        f"new state root: {new_state_root[:16]}..."
    )
    
    return receipts, new_state_root
```

## Testing Strategy

### 1. Unit Tests

**File**: `tests/test_state_sync.py`

```python
import pytest
from decimal import Decimal
from qrdx.contracts.state_sync import StateSyncManager, WEI_PER_QRDX

@pytest.mark.asyncio
async def test_sync_address_converts_correctly():
    """Test that QRDX → wei conversion is correct."""
    # Setup
    db = MockDatabase()
    evm_state = MockEVMState()
    sync = StateSyncManager(db, evm_state)
    
    # Set native balance
    await db.set_balance("0xTest", Decimal("1000.5"))  # 1000.5 QRDX
    
    # Sync
    await sync.sync_address_to_evm(
        address="0xTest",
        block_height=100,
        block_hash="0xBlock100"
    )
    
    # Verify EVM balance
    evm_balance = await evm_state.get_balance("0xTest")
    expected = int(Decimal("1000.5") * Decimal(WEI_PER_QRDX))
    assert evm_balance == expected
    
@pytest.mark.asyncio
async def test_sync_is_idempotent():
    """Test that syncing twice doesn't change balance."""
    # ... test implementation ...
    
@pytest.mark.asyncio
async def test_balance_change_recorded():
    """Test that balance changes are logged."""
    # ... test implementation ...
```

### 2. Integration Tests

**File**: `tests/test_contract_with_state_sync.py`

```python
@pytest.mark.asyncio
async def test_contract_deployment_with_funded_account():
    """
    Test full contract deployment flow:
    1. Account funded in genesis
    2. Balance synced to EVM
    3. Contract deployed successfully
    4. Gas paid correctly
    """
    # ... test implementation ...
    
@pytest.mark.asyncio
async def test_multiple_transactions_same_block():
    """
    Test multiple contract transactions in one block.
    Each should sync balance correctly.
    """
    # ... test implementation ...
```

### 3. Consensus Tests

**File**: `tests/test_consensus_with_state_sync.py`

```python
@pytest.mark.asyncio
async def test_all_validators_compute_same_state_root():
    """
    Test that all validators compute identical state root
    given same transactions.
    """
    # Setup 4 validators
    validators = [Validator(i) for i in range(4)]
    
    # Each processes same transactions
    transactions = [...]
    
    state_roots = []
    for validator in validators:
        root = await validator.process_block(transactions)
        state_roots.append(root)
    
    # All must match
    assert len(set(state_roots)) == 1
```

## Migration Plan

### Phase 1: Database Migration (Non-Breaking)
**Duration**: 1 day
**Risk**: Low

1. Add new tables:
   - `evm_balance_sync_registry`
   - `evm_balance_changes`
   - `state_checkpoints`
2. No changes to existing code
3. Deploy to testnet

### Phase 2: Implement State Sync (Feature Flag)
**Duration**: 1 week
**Risk**: Medium

1. Implement `StateSyncManager`
2. Implement `ExecutionContext`
3. Add feature flag: `QRDX_ENABLE_STATE_SYNC=false` (default)
4. Add unit tests
5. Deploy to testnet with flag OFF

### Phase 3: Testing (Testnet Only)
**Duration**: 1 week
**Risk**: Medium

1. Enable flag on testnet: `QRDX_ENABLE_STATE_SYNC=true`
2. Run integration tests
3. Deploy contracts, test gas payments
4. Monitor for issues
5. Fix bugs

### Phase 4: RPC Integration (Testnet)
**Duration**: 3 days
**Risk**: Low

1. Update `eth_sendRawTransaction` handler
2. Test with Web3.js clients
3. Verify balance sync works correctly

### Phase 5: Validator Integration (Testnet)
**Duration**: 1 week
**Risk**: High

1. Update block proposal code
2. Coordinate testnet validator upgrade
3. Test consensus with state sync
4. Verify all validators compute same state root

### Phase 6: Mainnet Deployment
**Duration**: 1 day
**Risk**: High

1. Code freeze and audit
2. Coordinate mainnet upgrade (all validators)
3. Enable state sync
4. Monitor closely

## Performance Optimization

### Balance Caching
- Cache recently synced balances in memory
- Invalidate on block change
- Expected: 90%+ cache hit rate

### Batch Synchronization
- Sync multiple addresses in one DB query
- Use COPY for bulk inserts
- Expected: 10x faster for >100 addresses

### Lazy Merkle Tree Updates
- Only recompute changed branches
- Cache intermediate nodes
- Expected: O(log n) instead of O(n)

## Security Audit Checklist

- [ ] All operations are deterministic
- [ ] No race conditions between states
- [ ] Atomic transactions properly scoped
- [ ] Rollback works correctly
- [ ] State roots verifiable
- [ ] No way to create money
- [ ] No way to destroy money
- [ ] Gas payments can't be bypassed
- [ ] Signatures verified before sync
- [ ] Merkle proofs valid

## Success Criteria

✅ Contract deployment succeeds with funded genesis account
✅ Gas payments deducted correctly
✅ All validators compute same state root
✅ Rollbacks work atomically
✅ Performance: <50ms overhead per transaction
✅ No consensus failures
✅ Audit trail complete
✅ Zero critical bugs in 2 weeks of testnet operation

---

**Document Status**: ✅ Complete - Ready for Implementation
**Last Updated**: 2025
**Consensus Impact**: HIGH - Requires coordinated upgrade
**Complexity**: Medium-High
**Estimated Implementation Time**: 3-4 weeks
