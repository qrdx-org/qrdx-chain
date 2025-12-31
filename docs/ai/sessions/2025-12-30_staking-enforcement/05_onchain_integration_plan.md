# On-Chain Integration Implementation Plan

## Objective
Transform the consensus layer from genesis-based validator loading to production-ready on-chain stake verification using StakeTracker.sol contract integration.

## Current State
- ✅ Genesis-based validator funding working
- ✅ StakeTracker.sol fully implemented with all required functions
- ❌ No integration between consensus and contract
- ❌ Not production-ready (can be cheated by modifying genesis)

## Target Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                    QRDX Consensus Layer                     │
├─────────────────────────────────────────────────────────────┤
│                                                             │
│  Validator Component                                        │
│  ┌──────────────────────────────────────────────────┐      │
│  │                                                   │      │
│  │  1. Startup: Load validators from StakeTracker   │      │
│  │     → web3.eth.contract.functions                 │      │
│  │     → getActiveValidators()                       │      │
│  │     → Verify stakes >= MIN_STAKE                  │      │
│  │                                                   │      │
│  │  2. Per-Epoch: Refresh validator set              │      │
│  │     → Query contract every epoch                  │      │
│  │     → Update ValidatorSet dynamically             │      │
│  │     → Handle new registrations/exits              │      │
│  │                                                   │      │
│  │  3. Block Validation: Verify proposer on-chain    │      │
│  │     → Extract proposer from block                 │      │
│  │     → Lookup in StakeTracker contract             │      │
│  │     → Verify stake + pubkey match                 │      │
│  │                                                   │      │
│  └──────────────────────────────────────────────────┘      │
│                          ↓↑                                 │
│  ┌──────────────────────────────────────────────────┐      │
│  │      StakeTrackerReader (NEW)                    │      │
│  │  - Web3 provider connection                       │      │
│  │  - Contract ABI loading                           │      │
│  │  - get_active_validators()                        │      │
│  │  - verify_validator_stake()                       │      │
│  │  - get_validator_by_index()                       │      │
│  └──────────────────────────────────────────────────┘      │
│                          ↓↑                                 │
└─────────────────────────────────────────────────────────────┘
                           ↓↑
┌─────────────────────────────────────────────────────────────┐
│                  Blockchain State Layer                      │
├─────────────────────────────────────────────────────────────┤
│                                                             │
│  StakeTracker.sol @ 0x<contract-address>                   │
│  ┌──────────────────────────────────────────────────┐      │
│  │                                                   │      │
│  │  State Variables:                                 │      │
│  │  - validators: ValidatorInfo[]                    │      │
│  │  - MIN_STAKE = 100,000 QRDX                       │      │
│  │  - MAX_VALIDATORS = 150                           │      │
│  │  - totalStaked: uint256                           │      │
│  │                                                   │      │
│  │  Functions:                                       │      │
│  │  - registerValidator(pubkey, commission) ✅       │      │
│  │  - getActiveValidators() ✅                       │      │
│  │  - getValidator(address) ✅                       │      │
│  │  - slashValidator(index, reason) ✅               │      │
│  │  - requestExit() ✅                               │      │
│  │                                                   │      │
│  └──────────────────────────────────────────────────┘      │
│                                                             │
└─────────────────────────────────────────────────────────────┘
```

## Implementation Phases

### Phase 1: Contract Interface Layer (2-3 days)

**Files to Create:**

1. **`py-evm/eth/consensus/stake_tracker_abi.json`**
   - Extract ABI from compiled StakeTracker.sol
   - Include all view functions and events

2. **`py-evm/eth/consensus/stake_tracker_reader.py`**
   - StakeTrackerReader class
   - Web3 provider initialization
   - Contract interaction methods
   - Error handling and retries

**Key Features:**
- ✅ Read active validators from contract
- ✅ Verify validator stake amounts
- ✅ Get validator by index/address
- ✅ Handle RPC connection failures gracefully
- ✅ Cache contract calls for performance

### Phase 2: Validator Component Integration (3-4 days)

**Files to Modify:**

1. **`trinity/components/builtin/qrpos_validator/component.py`**
   - Add StakeTrackerReader initialization
   - Replace genesis loading with contract queries
   - Implement hybrid mode (contract first, genesis fallback)
   - Add configuration for RPC endpoint and contract address

2. **`trinity/config.py`**
   - Add `stake_tracker_address` config option
   - Add `qrdx_rpc_url` config option
   - Add `use_onchain_validators` flag

**Configuration Options:**
```python
# Environment variables
STAKE_TRACKER_ADDRESS=0x...
QRDX_RPC_URL=http://localhost:8545
USE_ONCHAIN_VALIDATORS=true  # or false for genesis-only mode
```

### Phase 3: Dynamic Validator Set Updates (2 days)

**Files to Modify:**

1. **`trinity/components/builtin/qrpos_validator/component.py`**
   - Add epoch transition handler
   - Refresh validator set from contract every epoch
   - Update ValidatorSet in consensus layer
   - Log changes (new registrations, exits, stake changes)

**Implementation:**
```python
async def _validator_loop(self):
    while self.manager.is_running:
        current_slot = self.consensus.get_current_slot()
        current_epoch = compute_epoch_at_slot(current_slot)
        
        # Epoch transition detection
        if current_epoch > self.last_processed_epoch:
            await self._refresh_validator_set(current_epoch)
            self.last_processed_epoch = current_epoch
        
        # Continue with block production duties
        await self._produce_block_if_assigned()
```

### Phase 4: Block Validation Enhancement (1-2 days)

**Files to Modify:**

1. **`trinity/components/builtin/new_block/component.py`**
   - Add on-chain proposer verification
   - Validate proposer has sufficient stake
   - Verify Dilithium pubkey matches contract
   - Reject blocks from unregistered validators

2. **`py-evm/eth/consensus/qrpos.py`**
   - Add `validate_block_proposer()` method
   - Query StakeTracker for proposer info
   - Verify signature against on-chain pubkey

### Phase 5: Genesis Hash Verification (1 day)

**Files to Modify:**

1. **`trinity/initialization.py`**
   - Add genesis hash calculation
   - Compare with expected hash (from config or env)
   - Reject modified genesis files
   - Log genesis hash on startup

**Implementation:**
```python
def verify_genesis_integrity(genesis_file: Path, expected_hash: str = None):
    """Verify genesis file has not been tampered with."""
    with open(genesis_file, 'rb') as f:
        actual_hash = hashlib.sha256(f.read()).hexdigest()
    
    if expected_hash and actual_hash != expected_hash:
        raise GenesisIntegrityError(
            f"Genesis file has been modified! "
            f"Expected: {expected_hash}, Got: {actual_hash}"
        )
    
    return actual_hash
```

### Phase 6: Testing & Validation (2-3 days)

**Files to Create:**

1. **`tests/test_stake_tracker_reader.py`**
   - Test contract reading functions
   - Mock Web3 provider
   - Test error handling

2. **`tests/test_onchain_validator_loading.py`**
   - Test validator loading from contract
   - Test fallback to genesis
   - Test epoch-based refresh

3. **`tests/test_onchain_block_validation.py`**
   - Test proposer verification against contract
   - Test invalid proposer rejection
   - Test stake verification

4. **Integration tests**
   - Deploy StakeTracker to local testnet
   - Register validators via contract
   - Verify consensus reads from contract
   - Test dynamic updates (new validator joins)

## Dependencies

### Python Packages to Add

```toml
# pyproject.toml additions
dependencies = [
    # ... existing ...
    "web3>=6.0.0",  # For contract interaction
    "eth-abi>=4.0.0",  # Already included
]
```

### Contract Deployment

Need to deploy StakeTracker.sol and capture:
- Contract address
- Deployment block number
- Network ID

## Configuration Strategy

### Hybrid Mode (Recommended for Transition)

**Phase A: Genesis Bootstrap (Week 1-2)**
```bash
USE_ONCHAIN_VALIDATORS=false  # Use genesis only
# Validators start with genesis-based setup
```

**Phase B: Hybrid (Week 3-4)**
```bash
USE_ONCHAIN_VALIDATORS=true  # Try contract first
STAKE_TRACKER_ADDRESS=0x...
QRDX_RPC_URL=http://localhost:8545
# Fallback to genesis if contract unavailable
```

**Phase C: Full On-Chain (Week 5+)**
```bash
USE_ONCHAIN_VALIDATORS=true  # Contract required
GENESIS_VALIDATORS_DEPRECATED=true  # Fail if contract unavailable
```

### Environment Variables

```bash
# Required for on-chain mode
export STAKE_TRACKER_ADDRESS=0x...
export QRDX_RPC_URL=http://localhost:8545

# Optional
export GENESIS_HASH=abc123...  # For integrity verification
export STAKE_TRACKER_REFRESH_EPOCHS=1  # Refresh every N epochs
export ONCHAIN_VALIDATOR_CACHE_TTL=300  # Cache for 5 minutes
```

## Migration Process

### Step 1: Deploy StakeTracker
```bash
cd contracts/staking
npx hardhat run scripts/deploy_stake_tracker.js --network testnet
# Output: StakeTracker deployed at 0x...
```

### Step 2: Register Genesis Validators
```bash
# For each genesis validator
node scripts/register_genesis_validator.js \
  --address 0x... \
  --pubkey 0x... \
  --stake 100000
```

### Step 3: Update Node Configuration
```bash
# Add to .env or export
export STAKE_TRACKER_ADDRESS=0x...
export USE_ONCHAIN_VALIDATORS=true
```

### Step 4: Restart Nodes with Hybrid Mode
```bash
trinity --enable-qrpos-validator --validator-index 0
# Should log: "Loading validators from StakeTracker contract..."
# Should log: "Loaded 4 validators from contract"
```

### Step 5: Test Dynamic Registration
```bash
# New validator registers
node scripts/register_validator.js \
  --pubkey 0x... \
  --stake 100000 \
  --commission 5

# Wait for next epoch
# Consensus should automatically pick up new validator
```

## Success Criteria

### Functional Requirements
- [ ] Consensus can read validators from StakeTracker.sol
- [ ] Validators loaded have correct stakes (from contract, not genesis)
- [ ] Per-epoch validator set refresh works
- [ ] New validators can register and join dynamically
- [ ] Block validation verifies proposer against contract
- [ ] Genesis hash verification prevents tampering
- [ ] Hybrid mode works (contract with genesis fallback)

### Performance Requirements
- [ ] Contract queries complete in < 500ms
- [ ] Epoch refresh doesn't block consensus
- [ ] Caching reduces redundant contract calls
- [ ] RPC failures don't crash validator

### Security Requirements
- [ ] Cannot cheat by modifying genesis (hash check)
- [ ] Cannot propose blocks without on-chain stake
- [ ] Cannot claim higher stake than deposited
- [ ] All nodes verify same on-chain state

### Testing Requirements
- [ ] All unit tests passing (>90% coverage)
- [ ] Integration tests with deployed contract
- [ ] Load testing with 100+ validators
- [ ] Failover testing (RPC down, contract unavailable)

## Risk Mitigation

### Risk 1: RPC Endpoint Failure
**Mitigation:**
- Implement retry logic with exponential backoff
- Fallback to genesis in degraded mode
- Cache contract responses
- Support multiple RPC endpoints

### Risk 2: Contract State Inconsistency
**Mitigation:**
- Use finalized blocks only (not latest)
- Verify state roots
- Compare results from multiple nodes
- Emit warnings on state mismatches

### Risk 3: Performance Degradation
**Mitigation:**
- Cache active validator list
- Only query contract at epoch boundaries
- Use batch calls for multiple validators
- Optimize ABI encoding/decoding

### Risk 4: Migration Issues
**Mitigation:**
- Hybrid mode for gradual transition
- Extensive testing on testnet
- Rollback plan (disable USE_ONCHAIN_VALIDATORS)
- Monitor logs for contract read errors

## Timeline Estimate

| Phase | Days | Deliverable |
|-------|------|-------------|
| Phase 1: Contract Interface | 2-3 | StakeTrackerReader module |
| Phase 2: Validator Integration | 3-4 | Hybrid validator loading |
| Phase 3: Dynamic Updates | 2 | Per-epoch refresh |
| Phase 4: Block Validation | 1-2 | On-chain proposer checks |
| Phase 5: Genesis Verification | 1 | Hash verification |
| Phase 6: Testing | 2-3 | Full test suite |
| **Total** | **11-15 days** | Production-ready integration |

## Next Steps

1. ✅ Create implementation plan (this document)
2. Extract StakeTracker ABI from compiled contract
3. Implement StakeTrackerReader class
4. Add Web3 dependencies
5. Integrate with validator component
6. Test on local testnet
7. Deploy to public testnet
8. Monitor and iterate

## References

- **StakeTracker Contract**: `contracts/staking/StakeTracker.sol`
- **Validator Component**: `trinity/components/builtin/qrpos_validator/component.py`
- **Consensus Layer**: `py-evm/eth/consensus/qrpos.py`
- **Genesis Config**: Generated by `scripts/start_multi_node_testnet.sh`
- **Decentralization Analysis**: `04_decentralization_analysis.md`
