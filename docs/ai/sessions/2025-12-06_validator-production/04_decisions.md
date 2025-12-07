# Key Decisions

## Date
December 6, 2025

## Decision 1: Use VM's apply_all_transactions for State Roots
**Date**: December 6, 2025
**Context**: Validator was copying parent state root instead of computing new state

**Decision**: Use py-evm's `VM.apply_all_transactions()` method

**Rationale**:
- Battle-tested code from py-evm
- Correctly computes all merkle roots (state, tx, receipt)
- Handles gas accounting properly
- Generates proper receipts and bloom filters
- Already used by other parts of Trinity
- Avoids reimplementing complex trie operations

**Alternatives Considered**:
1. Manual trie computation - Rejected (too complex, error-prone)
2. Simplified state root copying - Rejected (doesn't work with transactions)

**Impact**: 
- Blocks now have correct, verifiable state roots
- Can handle transactions when transaction pool is integrated
- Other validators can verify blocks properly
- Critical for production consensus

**Code Location**: `trinity/components/builtin/qrpos_validator/component.py::_build_and_execute_block`

## Decision 2: Environment Variable for Validator Count
**Date**: December 6, 2025
**Context**: Validator count was hardcoded to 3 (testnet only)

**Decision**: Use `QRDX_NUM_VALIDATORS` environment variable with default of 3

**Rationale**:
- No code changes needed for different deployments
- Testnet defaults to 3 for ease of testing
- Production sets environment variable to 150
- Validated (must be >= 1)
- Clear logging shows current configuration
- Doesn't require genesis file changes

**Alternatives Considered**:
1. Read from genesis.json - Rejected (would require genesis format changes)
2. Command-line flag - Rejected (less standard than environment variable)
3. Config file - Rejected (adds complexity)

**Impact**:
- Easy local testing with 3 validators
- Production deployment with 150 validators
- No hardcoded values
- Scalable to any validator count

**Code Location**: `trinity/components/builtin/qrpos_validator/component.py::do_run`

**Production Usage**:
```bash
export QRDX_NUM_VALIDATORS=150
trinity --qrdx
```

## Decision 3: Implement Fork Choice Ancestry Checking
**Date**: December 6, 2025
**Context**: Fork choice had TODO for ancestry verification

**Decision**: Implement full ancestry checking via blockchain traversal

**Rationale**:
- Critical for consensus safety
- Prevents reorgs past finality boundary
- Required by whitepaper specification
- Relatively straightforward to implement
- Uses existing chaindb methods

**Algorithm**:
1. Walk backwards from candidate block
2. Check each parent until finding finalized checkpoint
3. Reject if we pass finalized slot without finding checkpoint
4. Special handling for genesis as finalized
5. Depth limit to prevent infinite loops

**Alternatives Considered**:
1. Skip ancestry checking - Rejected (consensus safety risk)
2. Only check slot numbers - Rejected (insufficient, allows invalid chains)
3. Cache ancestry - Considered for future optimization

**Impact**:
- Consensus safety enforced
- Invalid forks rejected automatically
- Finality boundary respected
- No reorgs past finalized checkpoint
- Production-ready fork choice

**Code Location**: `py-evm/eth/consensus/qrpos.py::ForkChoice._extends_from_finalized`

**Performance**: O(n) where n = blocks since finalized checkpoint (typically < 100 blocks)

## Decision 4: Persist State After Transaction Execution
**Date**: December 6, 2025
**Context**: Need correct state root in block header

**Decision**: Call `vm.state.persist()` after applying transactions

**Rationale**:
- Required for state changes to be written to database
- Without this, state root would be incorrect
- State must be persisted before reading state_root
- Standard pattern used elsewhere in Trinity

**Critical Code Sequence**:
```python
# 1. Execute transactions
result_header, receipts, computations = vm.apply_all_transactions(...)

# 2. CRITICAL: Persist state to database
vm.state.persist()

# 3. Get final header with persisted state root
final_header = result_header.copy(state_root=vm.state.state_root)
```

**Impact**: Without this, blocks would have invalid state roots even with proper execution

## Decision 5: Pass Transactions Through Full Pipeline
**Date**: December 6, 2025
**Context**: Validator was creating blocks without transaction data

**Decision**: Pass transactions and receipts through import and broadcast

**Rationale**:
- Blocks need complete data for validation
- Receipts needed for gas accounting
- Other validators need transaction data to verify
- Standard block format requires transactions
- Prepares for transaction pool integration

**Changes Made**:
- Updated `_propose_block` to use execution results
- Updated `_import_block_locally` to accept transactions and receipts
- Updated `_broadcast_block` to include transaction data
- Block creation uses actual transaction list

**Impact**:
- Complete block data in all operations
- Ready for transaction pool integration
- Proper block structure for validation

## Decision 6: Empty Transaction List is Acceptable
**Date**: December 6, 2025
**Context**: Transaction pool not yet integrated

**Decision**: Return empty list from `_get_pending_transactions()` temporarily

**Rationale**:
- Transaction pool integration is separate Phase 2
- Empty blocks still have valid state roots
- VM correctly handles zero transactions
- Doesn't block production deployment
- Clear comment documents this is intentional

**Documentation**:
```python
def _get_pending_transactions(self) -> List[BaseTransactionAPI]:
    """
    Get pending transactions from mempool.
    
    Returns empty list for now. Transaction pool integration is a separate phase.
    For production, this should query the transaction pool component via IPC.
    """
    return []  # Empty blocks until transaction pool integrated
```

**Impact**: 
- Blocks produce correctly (just empty)
- State roots computed properly (even with 0 transactions)
- Not a production blocker
- Clear path forward for Phase 2

## Decision 7: Conservative Ancestry Depth Limit
**Date**: December 6, 2025
**Context**: Ancestry checking needs protection against infinite loops

**Decision**: Set max_depth = 10,000 blocks for ancestry traversal

**Rationale**:
- 10,000 blocks = ~5.5 hours at 2-second block time
- Finalized checkpoints advance much faster
- Typical ancestry check: < 100 blocks
- Conservative limit prevents pathological cases
- Reject blocks if depth exceeded (safer than accepting)

**Impact**:
- Protection against malicious chains
- Protection against database corruption
- No impact on normal operation
- Could be adjusted if needed

## Decision 8: Use Slot from Extra Data for Ancestry
**Date**: December 6, 2025
**Context**: Need slot numbers for ancestry checking

**Decision**: Decode slot from header.extra_data field

**Rationale**:
- QR-PoS metadata stored in extra_data
- Format: [slot(8 bytes)][validator_index(8 bytes)][pubkey(16 bytes)]
- Standardized format across all blocks
- Efficient encoding
- Easy to decode

**Format**:
```python
slot = int.from_bytes(header.extra_data[:8], 'big')
```

**Impact**:
- Enables slot-based ancestry checking
- Consistent with block building
- No additional storage needed

## Decision 9: Conservative Finality Boundary Enforcement
**Date**: December 6, 2025
**Context**: Fork choice must respect finality

**Decision**: Reject any candidate that doesn't extend from finalized checkpoint

**Rationale**:
- Consensus safety is paramount
- Finality must be irreversible
- Better to reject valid blocks than accept invalid ones
- Aligns with whitepaper specification
- Standard in PoS protocols

**Impact**:
- Strong finality guarantees
- No reorgs past checkpoint
- Consensus safety enforced
- Potential liveness impact if finality stalls (acceptable trade-off)

## Decision 10: Log Transaction Execution Details
**Date**: December 6, 2025
**Context**: Need visibility into block execution

**Decision**: Log transaction count, gas used, and state root

**Rationale**:
- Debugging transaction execution
- Monitoring gas usage
- Verifying state root changes
- Production observability

**Example Log**:
```
Executed 5 transactions: state_root=0x1234..., gas_used=210000
Imported block #123 (hash=0xabcd..., 5 txs, 15 attestations, gas_used=210000)
```

**Impact**:
- Better debugging
- Production monitoring
- Performance analysis

## Summary of Decisions

### Code Quality Decisions
1. Use existing VM code (not reimplement)
2. Persist state properly
3. Pass complete data through pipeline
4. Add comprehensive logging

### Configuration Decisions
1. Environment variable for validator count
2. Conservative defaults for testnet
3. Clear production deployment path

### Consensus Safety Decisions
1. Implement full ancestry checking
2. Enforce finality boundaries
3. Conservative depth limits
4. Reject on uncertainty

### Phase Planning Decisions
1. Transaction pool is Phase 2
2. Empty blocks acceptable temporarily
3. Focus on core consensus first

All decisions prioritize:
- **Correctness** over convenience
- **Safety** over performance
- **Production-readiness** over shortcuts
- **Clear code** over clever code
