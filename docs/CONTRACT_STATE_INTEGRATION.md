# Contract State Integration Issue & Solution

## Issue Summary

**Problem**: EVM contract execution fails with "Account Balance cannot be negative" errors, even though accounts have sufficient QRDX balance in the genesis/chain state.

**Root Cause**: The EVM has an isolated state management system (`ContractStateManager`) that is completely separate from the QRDX blockchain state (`Database.get_address_balance`). When a contract transaction is executed:

1. ✅ Transaction is properly signed with ECDSA
2. ✅ Signature is verified by recovering sender address  
3. ✅ Sender has 1B QRDX in chain state (genesis allocation)
4. ❌ **EVM state has no knowledge of this balance**
5. ❌ EVM tries to deduct gas costs from sender's EVM balance (which is 0)
6. ❌ Transaction fails with negative balance error

## Current Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                         QRDX Blockchain                         │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│  ┌──────────────────────────┐    ┌──────────────────────────┐ │
│  │   QRDX Chain State       │    │   EVM Contract State     │ │
│  │   (Database)             │    │   (ContractStateManager) │ │
│  ├──────────────────────────┤    ├──────────────────────────┤ │
│  │ • Account balances       │    │ • Account balances       │ │
│  │ • UTXOs                  │    │ • Contract storage       │ │
│  │ • Transaction history    │    │ • Contract code          │ │
│  │ • Block data             │    │ • Account nonces         │ │
│  │ • Validator state        │    │ • Storage tries          │ │
│  └──────────────────────────┘    └──────────────────────────┘ │
│           ↕                                ↕                   │
│      PostgreSQL                       PostgreSQL               │
│    (transactions,                  (account_state,             │
│     unspent_outputs,               contract_storage,           │
│     blocks tables)                 contract_code tables)       │
│                                                                 │
│  ❌ NO SYNCHRONIZATION BETWEEN STATES                          │
│                                                                 │
└─────────────────────────────────────────────────────────────────┘
```

## Security Requirements

For a **decentralized and secure** solution, we must ensure:

### 1. **Deterministic State Transitions**
- All nodes must compute identical state given the same transactions
- No non-deterministic operations (timestamps, random numbers, external APIs)
- State updates must be reproducible across the network

### 2. **Consensus-Safe Integration**  
- Balance synchronization must happen at predictable points
- All validators must see the same balances at the same block height
- No race conditions between chain state and EVM state

### 3. **Atomic Operations**
- Balance transfers between chain and EVM must be atomic
- Either both states update or neither updates (no partial failures)
- Rollbacks must work correctly for failed transactions

### 4. **Prevention of Double-Spending**
- QRDX tokens can only exist in one state at a time
- Moving tokens to EVM must lock/burn them in chain state
- Moving tokens from EVM must mint/unlock them in chain state

### 5. **Cryptographic Verification**
- All balance changes must be verifiable by signature
- State roots must be computed and verified
- No trusted oracles or centralized components

## Proposed Solution Architecture

```
┌────────────────────────────────────────────────────────────────────────┐
│                         QRDX Unified State                             │
├────────────────────────────────────────────────────────────────────────┤
│                                                                        │
│  ┌──────────────────────────┐         ┌──────────────────────────┐  │
│  │   QRDX Native State      │  ←───→  │   EVM Contract State     │  │
│  │   (UTXO Model)           │         │   (Account Model)        │  │
│  └──────────────────────────┘         └──────────────────────────┘  │
│              ↓                                     ↑                  │
│       ┌─────────────────────────────────────────────┐                │
│       │     State Bridge (Bidirectional)            │                │
│       ├─────────────────────────────────────────────┤                │
│       │                                             │                │
│       │  • Lock QRDX → Mint EVM balance             │                │
│       │  • Burn EVM balance → Unlock QRDX           │                │
│       │  • Atomic state transitions                 │                │
│       │  • Merkle proof verification                │                │
│       │  • Consensus-safe checkpointing             │                │
│       │                                             │                │
│       └─────────────────────────────────────────────┘                │
│                           ↓                                           │
│              ┌────────────────────────────┐                          │
│              │   Unified State Root       │                          │
│              │   (Merkle Tree)            │                          │
│              │                            │                          │
│              │  root = keccak256(         │                          │
│              │    chain_state_root +      │                          │
│              │    evm_state_root          │                          │
│              │  )                         │                          │
│              └────────────────────────────┘                          │
│                                                                        │
└────────────────────────────────────────────────────────────────────────┘
```

## Implementation Plan

### Phase 1: State Bridge Contract (Foundation)
**File**: `qrdx/contracts/state_bridge.py`

```python
class StateBridge:
    """
    Bidirectional bridge between QRDX native state and EVM state.
    
    This is a CONSENSUS-CRITICAL component. All nodes must execute
    this identically to maintain network consensus.
    """
    
    def __init__(self, db: Database, state_manager: ContractStateManager):
        self.db = db
        self.state_manager = state_manager
        self.locked_utxos = {}  # UTXO hash -> EVM address mapping
    
    async def lock_qrdx_for_evm(
        self,
        sender_address: str,
        amount: int,  # in smallest unit (satoshis)
        tx_hash: str
    ) -> bool:
        """
        Lock QRDX in native state and credit EVM balance.
        
        This creates a provable lock that can be verified by all nodes.
        
        Args:
            sender_address: QRDX address (can be PQ or traditional)
            amount: Amount to lock (smallest unit)
            tx_hash: Transaction hash proving the lock
            
        Returns:
            True if lock successful
        """
        # 1. Verify transaction exists and has required amount
        # 2. Mark UTXOs as locked (create special output type)
        # 3. Credit EVM account with equivalent balance
        # 4. Store lock proof in database
        # 5. Update Merkle proof
        pass
    
    async def unlock_qrdx_from_evm(
        self,
        evm_address: str,
        qrdx_address: str,
        amount: int,
        burn_proof: bytes
    ) -> bool:
        """
        Burn EVM balance and unlock QRDX in native state.
        
        Args:
            evm_address: EVM address to burn from
            qrdx_address: QRDX address to receive unlocked tokens
            amount: Amount to unlock
            burn_proof: Merkle proof of EVM balance burn
            
        Returns:
            True if unlock successful
        """
        # 1. Verify burn proof
        # 2. Deduct from EVM balance (atomic)
        # 3. Create unlocked UTXOs for recipient
        # 4. Update both state roots
        pass
    
    async def sync_balance_to_evm(
        self,
        address: str,
        block_height: int
    ) -> None:
        """
        Sync current QRDX balance to EVM state.
        
        Called at specific block boundaries to maintain consistency.
        
        Args:
            address: Address to sync
            block_height: Current block height (for determinism)
        """
        # Get QRDX balance from chain state
        qrdx_balance = await self.db.get_address_balance(address)
        
        # Convert Decimal QRDX to wei (EVM's smallest unit)
        # 1 QRDX = 10^18 wei (Ethereum compatibility)
        wei_balance = int(qrdx_balance * Decimal(10**18))
        
        # Update EVM state
        await self.state_manager.set_balance(address, wei_balance)
        
        logger.info(
            f"Synced balance for {address}: "
            f"{qrdx_balance} QRDX → {wei_balance} wei "
            f"at block {block_height}"
        )
```

### Phase 2: Execution Context Integration
**File**: `qrdx/contracts/execution_context.py`

```python
@dataclass
class ExecutionContext:
    """
    Execution context for contract transactions.
    
    Combines blockchain state with EVM state for unified execution.
    """
    
    block_height: int
    block_timestamp: int
    block_hash: str
    chain_state: Database
    evm_state: ContractStateManager
    state_bridge: StateBridge
    
    async def prepare_execution(self, sender: str) -> None:
        """
        Prepare execution environment.
        
        1. Sync sender's QRDX balance to EVM
        2. Load contract state
        3. Create snapshot for potential rollback
        """
        # Sync balance before execution
        await self.state_bridge.sync_balance_to_evm(
            sender,
            self.block_height
        )
        
        # Create state snapshot
        self.evm_state.snapshot()
    
    async def finalize_execution(
        self,
        success: bool,
        gas_used: int,
        gas_price: int
    ) -> None:
        """
        Finalize execution and update both states.
        
        Args:
            success: Whether execution succeeded
            gas_used: Gas consumed
            gas_price: Gas price in wei
        """
        if success:
            # Commit EVM state changes
            await self.evm_state.commit()
            
            # Update chain state (gas fees, etc.)
            # This is where we'd handle validator rewards
        else:
            # Revert EVM state changes
            await self.evm_state.revert()
```

### Phase 3: Contract Transaction Handler
**File**: `qrdx/contracts/transaction_handler.py`

```python
class ContractTransactionHandler:
    """
    Handles contract transactions with proper state management.
    """
    
    def __init__(
        self,
        db: Database,
        state_manager: ContractStateManager,
        evm_executor: QRDXEVMExecutor
    ):
        self.db = db
        self.state_manager = state_manager
        self.executor = evm_executor
        self.bridge = StateBridge(db, state_manager)
    
    async def execute_contract_transaction(
        self,
        sender: bytes,
        to: Optional[bytes],
        value: int,
        data: bytes,
        gas: int,
        gas_price: int,
        block_height: int,
        block_hash: str
    ) -> EVMResult:
        """
        Execute contract transaction with full state integration.
        
        This is the MAIN ENTRY POINT for contract execution.
        """
        sender_addr = encode_hex(sender)
        
        # Create execution context
        context = ExecutionContext(
            block_height=block_height,
            block_timestamp=int(time.time()),
            block_hash=block_hash,
            chain_state=self.db,
            evm_state=self.state_manager,
            state_bridge=self.bridge
        )
        
        # Prepare (sync balances)
        await context.prepare_execution(sender_addr)
        
        try:
            # Execute in EVM
            result = self.executor.execute(
                sender=sender,
                to=to,
                value=value,
                data=data,
                gas=gas,
                gas_price=gas_price
            )
            
            # Finalize (commit or revert)
            await context.finalize_execution(
                success=result.success,
                gas_used=result.gas_used,
                gas_price=gas_price
            )
            
            return result
            
        except Exception as e:
            # Always revert on exception
            await context.finalize_execution(
                success=False,
                gas_used=0,
                gas_price=0
            )
            raise
```

### Phase 4: Database Schema Updates

**SQL Migration**: Create tables for state bridge

```sql
-- Lock records for QRDX→EVM transfers
CREATE TABLE IF NOT EXISTS evm_lock_records (
    lock_id SERIAL PRIMARY KEY,
    tx_hash CHAR(64) NOT NULL UNIQUE,
    qrdx_address TEXT NOT NULL,
    evm_address TEXT NOT NULL,
    amount BIGINT NOT NULL,
    block_height INTEGER NOT NULL,
    locked_at TIMESTAMP NOT NULL DEFAULT NOW(),
    merkle_proof TEXT NOT NULL,
    INDEX idx_qrdx_addr (qrdx_address),
    INDEX idx_evm_addr (evm_address),
    INDEX idx_block_height (block_height)
);

-- Unlock records for EVM→QRDX transfers  
CREATE TABLE IF NOT EXISTS evm_unlock_records (
    unlock_id SERIAL PRIMARY KEY,
    burn_tx_hash CHAR(64) NOT NULL UNIQUE,
    evm_address TEXT NOT NULL,
    qrdx_address TEXT NOT NULL,
    amount BIGINT NOT NULL,
    block_height INTEGER NOT NULL,
    unlocked_at TIMESTAMP NOT NULL DEFAULT NOW(),
    burn_proof TEXT NOT NULL,
    INDEX idx_evm_addr (evm_address),
    INDEX idx_qrdx_addr (qrdx_address)
);

-- Balance sync checkpoints (for verification)
CREATE TABLE IF NOT EXISTS balance_sync_checkpoints (
    checkpoint_id SERIAL PRIMARY KEY,
    address TEXT NOT NULL,
    block_height INTEGER NOT NULL,
    qrdx_balance NUMERIC(20, 8) NOT NULL,
    evm_balance BIGINT NOT NULL,
    state_root CHAR(64) NOT NULL,
    synced_at TIMESTAMP NOT NULL DEFAULT NOW(),
    UNIQUE(address, block_height),
    INDEX idx_address (address),
    INDEX idx_block_height (block_height)
);
```

### Phase 5: RPC Handler Updates

**File**: `qrdx/node/main.py` (update eth_sendRawTransaction)

```python
async def eth_sendRawTransaction_handler(raw_tx_hex):
    """Send a pre-signed raw transaction with full state integration."""
    try:
        # ... existing signature verification code ...
        
        # Get current block height for determinism
        current_block = await db.get_last_block()
        block_height = current_block.block_height
        block_hash = current_block.block_hash
        
        # Create transaction handler with state bridge
        tx_handler = ContractTransactionHandler(
            db=db,
            state_manager=state_manager,
            evm_executor=evm_executor
        )
        
        # Execute with full state integration
        result = await tx_handler.execute_contract_transaction(
            sender=sender,
            to=to_bytes if to_bytes else None,
            value=value_wei,
            data=data,
            gas=gas,
            gas_price=gas_price_wei,
            block_height=block_height,
            block_hash=block_hash
        )
        
        # ... rest of handler ...
```

## Testing Strategy

### Unit Tests
```python
# tests/test_state_bridge.py
async def test_lock_qrdx_for_evm():
    """Test locking QRDX creates correct EVM balance."""
    
async def test_unlock_qrdx_from_evm():
    """Test burning EVM balance unlocks QRDX."""
    
async def test_balance_sync():
    """Test balance synchronization is deterministic."""
    
async def test_atomic_failure():
    """Test that failed transactions revert both states."""
```

### Integration Tests
```python
# tests/test_contract_integration.py
async def test_end_to_end_contract_deployment():
    """Test full contract deployment with balance sync."""
    
async def test_contract_interaction_with_value():
    """Test contract calls that transfer value."""
    
async def test_multiple_transactions_same_block():
    """Test multiple contract txs in one block."""
```

### Consensus Tests
```python
# tests/test_consensus_safety.py
async def test_deterministic_state_root():
    """Verify all nodes compute same state root."""
    
async def test_balance_sync_at_epoch():
    """Test balance sync at epoch boundaries."""
```

## Migration Path

### Step 1: Add State Bridge (Non-Breaking)
- Implement `StateBridge` class
- Add database tables
- No changes to existing functionality

### Step 2: Optional State Sync (Testing)
- Add optional balance sync in RPC handler
- Use environment variable to enable: `QRDX_EVM_BALANCE_SYNC=true`
- Test extensively on testnet

### Step 3: Make Required (Consensus Upgrade)
- After testing, make balance sync mandatory
- Coordinate network upgrade
- All validators must upgrade simultaneously

### Step 4: Finalize Bridge (Future)
- Implement full lock/unlock mechanisms
- Add Merkle proof verification
- Enable cross-chain token transfers

## Security Considerations

1. **Reentrancy Protection**: State bridge must prevent reentrancy attacks
2. **Overflow Protection**: All balance arithmetic must check for overflow
3. **Access Control**: Only contract execution can trigger state bridge
4. **Audit Trail**: All state changes must be logged and verifiable
5. **Emergency Pause**: Ability to pause bridge in case of discovered vulnerability

## Performance Impact

- **Balance Sync Cost**: O(1) database lookup per transaction
- **State Root Update**: O(log n) Merkle tree update
- **Storage Overhead**: ~200 bytes per lock/unlock record
- **Expected Impact**: <10ms additional latency per contract transaction

## Rollout Timeline

1. **Week 1**: Implement `StateBridge` and database schema
2. **Week 2**: Add `ExecutionContext` and `ContractTransactionHandler`  
3. **Week 3**: Update RPC handlers and add unit tests
4. **Week 4**: Integration testing on local testnet
5. **Week 5**: Deploy to public testnet
6. **Week 6**: Monitor, fix issues, stress test
7. **Week 7**: Code audit and security review
8. **Week 8**: Mainnet deployment (coordinated upgrade)

## Success Criteria

✅ Contract transactions succeed without balance errors
✅ All nodes compute identical state roots
✅ Balances sync correctly at block boundaries  
✅ Failed transactions revert both states atomically
✅ No double-spending possible
✅ Deterministic execution across all validators
✅ Consensus maintained through state transitions
✅ Merkle proofs verifiable by any node
✅ Emergency rollback works correctly
✅ Performance meets requirements (<100ms per tx)

---

**Status**: 📋 Design Complete - Ready for Implementation
**Priority**: 🔴 Critical - Blocks contract functionality
**Complexity**: 🔶 High - Consensus-critical changes
**Risk**: ⚠️ Medium - Requires careful testing and coordination
