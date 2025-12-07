# Implementation Plan: Transaction Execution and State Roots

## Date
December 6, 2025

## Objective
Implement production-ready transaction execution and state root computation in the validator component.

## Current Issues

### Critical TODOs to Fix
1. `state_root=parent.state_root` - Just copying parent, not computing new state
2. `transaction_root=Hash32(b'\x00' * 32)` - Zero hash, not real tx root  
3. `receipt_root=Hash32(b'\x00' * 32)` - Zero hash, not real receipt root
4. `bloom=0` - Zero bloom, not computed from receipts
5. `gas_used=0` - Zero gas, not summed from receipts
6. `_get_pending_transactions()` - Returns empty list

## Solution Architecture

### Approach: Use VM's `apply_all_transactions` Method
The VM already has a production-ready method for this:

```python
vm.apply_all_transactions(
    transactions: Sequence[SignedTransactionAPI],
    base_header: BlockHeaderAPI
) -> Tuple[BlockHeaderAPI, Tuple[ReceiptAPI, ...], Tuple[ComputationAPI, ...]]
```

This method:
1. Executes each transaction
2. Generates receipts
3. Updates state trie
4. Computes all roots (state, transaction, receipt)
5. Computes bloom filter
6. Computes gas used
7. Returns a complete header with ALL correct values

### Implementation Steps

#### Step 1: Get VM Instance
```python
from trinity._utils.connect import get_eth1_chain_with_remote_db

with get_eth1_chain_with_remote_db(self.boot_info, self.event_bus) as chain:
    vm = chain.get_vm()
```

#### Step 2: Get Transactions
```python
# For now, empty list is OK
# TODO: Query transaction pool in Phase 2
transactions = await self._get_pending_transactions()
```

#### Step 3: Execute Transactions
```python
# Build base header (without correct roots)
base_header = parent_header.copy(
    block_number=parent_header.block_number + 1,
    timestamp=int(time.time()),
    extra_data=qrpos_extra_data,
    difficulty=0,
    parent_hash=parent_header.hash,
    # ... other fields
)

# Apply all transactions and get complete header
result_header, receipts, computations = vm.apply_all_transactions(
    transactions,
    base_header
)

# result_header now has:
# - Correct state_root
# - Correct transaction_root
# - Correct receipt_root
# - Correct bloom
# - Correct gas_used
```

#### Step 4: Persist State
```python
# CRITICAL: Must persist state to database
vm.state.persist()

# Update header with persisted state root
final_header = result_header.copy(
    state_root=vm.state.state_root
)
```

#### Step 5: Use Final Header
```python
# Sign this header (has correct roots)
signature = self._sign_block(final_header)

# Create block with transactions
block = Block(
    header=final_header,
    transactions=transactions,
    uncles=[]
)
```

## Code Changes Required

### File: trinity/components/builtin/qrpos_validator/component.py

#### Change 1: Remove TODOs from `_build_block_header`
**Before**:
```python
async def _build_block_header(self, parent: BlockHeader, transactions: List[BaseTransactionAPI]) -> BlockHeader:
    # ... calculate block_number, timestamp, etc ...
    
    header = BlockHeader(
        # ... basic fields ...
        state_root=parent.state_root,  # TODO: Compute after executing txs
        transaction_root=Hash32(b'\x00' * 32),  # TODO: Compute from transactions
        receipt_root=Hash32(b'\x00' * 32),  # TODO: Compute from receipts
        bloom=0,  # TODO: Compute from receipts
        gas_used=0,  # TODO: Sum from receipts
        # ... other fields ...
    )
    
    return header
```

**After**:
```python
async def _build_and_execute_block(
    self,
    parent: BlockHeader,
    transactions: List[BaseTransactionAPI],
) -> Tuple[BlockHeader, Tuple[ReceiptAPI, ...], Tuple[ComputationAPI, ...]]:
    """
    Build block header and execute all transactions.
    
    Returns complete header with correct state/transaction/receipt roots.
    """
    from trinity._utils.connect import get_eth1_chain_with_remote_db
    
    # Calculate basic fields
    block_number = parent.block_number + 1
    timestamp = int(time.time())
    
    # Encode QR-PoS data
    proposer_pubkey = self.validator_key.public_key().to_bytes()
    extra_data = (
        self.current_slot.to_bytes(8, 'big') +
        self.validator_index.to_bytes(8, 'big') +
        proposer_pubkey[:16]
    )
    
    # Create base header (will be updated by VM)
    base_header = parent.copy(
        difficulty=0,
        block_number=block_number,
        gas_limit=parent.gas_limit,
        timestamp=timestamp,
        coinbase=Address(proposer_pubkey[:20]),
        parent_hash=parent.hash,
        uncles_hash=EMPTY_UNCLE_HASH,
        extra_data=extra_data,
        mix_hash=Hash32(b'\x00' * 32),
        nonce=b'\x00' * 8,
    )
    
    # Get VM and execute transactions
    with get_eth1_chain_with_remote_db(self.boot_info, self.event_bus) as chain:
        vm = chain.get_vm(base_header)
        
        # Execute all transactions - this computes all roots correctly
        result_header, receipts, computations = vm.apply_all_transactions(
            transactions,
            base_header
        )
        
        # Persist state to database
        vm.state.persist()
        
        # Update header with persisted state root
        final_header = result_header.copy(
            state_root=vm.state.state_root
        )
    
    return final_header, receipts, computations
```

#### Change 2: Update `_propose_block` to use new method
**Replace**:
```python
# Build block header
header = await self._build_block_header(parent_header, transactions)
```

**With**:
```python
# Build block header and execute transactions
header, receipts, computations = await self._build_and_execute_block(
    parent_header,
    transactions
)
```

#### Change 3: Update `_import_block_locally` signature
**Before**:
```python
async def _import_block_locally(self, header: BlockHeader, signature: bytes, attestations: List) -> None:
```

**After**:
```python
async def _import_block_locally(
    self,
    header: BlockHeader,
    signature: bytes,
    attestations: List,
    transactions: List[BaseTransactionAPI],
    receipts: Tuple[ReceiptAPI, ...],
) -> None:
```

#### Change 4: Update block import call
**Replace**:
```python
await self._import_block_locally(header, signature, attestations)
```

**With**:
```python
await self._import_block_locally(header, signature, attestations, transactions, receipts)
```

#### Change 5: Update broadcast call
**Replace**:
```python
await self._broadcast_block(header, signature)
```

**With**:
```python
await self._broadcast_block(header, signature, transactions)
```

## Benefits

1. ✅ **Production-Ready**: Uses battle-tested VM execution code
2. ✅ **Correct State Roots**: VM computes proper merkle roots
3. ✅ **Correct Transaction Roots**: VM computes from transaction list
4. ✅ **Correct Receipt Roots**: VM computes from receipts
5. ✅ **Correct Bloom Filter**: VM computes from receipt logs
6. ✅ **Correct Gas Used**: VM sums from transaction executions
7. ✅ **No TODOs**: All stub code removed

## Testing Plan

### Unit Tests
1. Test with zero transactions (empty block)
2. Test with simple value transfer
3. Test with contract deployment
4. Test with contract call
5. Test gas limit enforcement
6. Test invalid transactions rejected

### Integration Tests
1. Multi-node testnet with transactions
2. Verify state roots match across nodes
3. Verify blocks validate correctly
4. Verify chain progresses with transactions

## Risks and Mitigations

### Risk 1: VM State Persistence
**Problem**: State must be persisted correctly
**Mitigation**: Call `vm.state.persist()` after execution

### Risk 2: Transaction Pool Integration
**Problem**: Need real transactions eventually
**Mitigation**: Phase 2 task, empty list works for now

### Risk 3: Performance
**Problem**: Transaction execution may be slow
**Mitigation**: Monitor and optimize, acceptable for 2-second slots

## Next Phase: Transaction Pool

After this is working:
1. Create transaction pool component
2. Implement IPC communication
3. Query pending transactions
4. Apply selection logic (gas limit, nonce ordering, etc.)
5. Include real transactions in blocks

## Success Criteria

- [ ] All TODOs removed from validator code
- [ ] State roots computed correctly
- [ ] Transaction roots computed correctly  
- [ ] Receipt roots computed correctly
- [ ] Bloom filters computed correctly
- [ ] Gas used computed correctly
- [ ] Blocks validate on peer nodes
- [ ] Tests passing
- [ ] No production blockers
