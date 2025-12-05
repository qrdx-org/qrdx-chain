# QR-PoS Phase 3 Implementation Roadmap

## Current Status (December 3, 2025)

### ✅ Completed
- **Phase 1**: Quantum-resistant signatures (Dilithium) integrated
- **Phase 2**: Block creation with QR-PoS consensus
  - 150 validators in genesis
  - Round-robin block proposer selection
  - 2-second slot intervals
  - Dilithium signatures (3,309 bytes)
  - P2P block propagation via NewBlockHashes
- **Phase 3 Partial**: Attestation creation
  - Validators create attestations every slot
  - Attestations reference parent block and slot number
- **Python 3.12 Compatibility**: All dependencies upgraded/fixed
  - async-lru upgraded to 2.0.4
  - JSON-RPC re-enabled and working
- **Infrastructure**: 
  - Multi-node testnet script functional
  - IPC event bus operational
  - JSON-RPC HTTP server running

### ⚠️ Known Issues
1. Genesis timestamp = 0 (causing high slot numbers ~88000+)
2. HTTP server port randomization (9829 instead of configured 9391)
3. Some RPC methods hanging (net_version timeout)
4. IPC event delivery investigation incomplete

---

## Step 1: JSON-RPC Testing & Web3.py Compatibility ⏳

### Objectives
- Verify all standard Ethereum JSON-RPC methods work correctly
- Test web3.py library compatibility
- Ensure production-ready RPC interface (no stubs)
- Fix HTTP server port configuration issue

### Tasks

#### 1.1 Fix HTTP Server Port Configuration
**Priority**: High  
**File**: `trinity/components/builtin/json_rpc/component.py`  
**Issue**: Server starting on random port instead of configured port  
**Action**: Debug why `--http-port` argument not being respected

#### 1.2 Test Core RPC Methods
**Priority**: High  
**Methods to Test**:
- ✅ `eth_blockNumber` - WORKING (returns 0x0)
- ⏳ `eth_getBlockByNumber` - Test with genesis block
- ⏳ `eth_getBlockByHash` - Test with genesis block
- ⏳ `eth_chainId` - Should return 1337
- ⏳ `net_version` - Currently hanging, needs fix
- ⏳ `web3_clientVersion` - Should return Trinity version
- ⏳ `net_listening` - Should return true
- ⏳ `net_peerCount` - Should return 1 (peer count)
- ⏳ `eth_syncing` - Should return false (not syncing)
- ⏳ `eth_gasPrice` - Should return configured value
- ⏳ `eth_accounts` - Should return validator accounts
- ⏳ `eth_getBalance` - Test with genesis accounts
- ⏳ `eth_call` - Test contract calls
- ⏳ `eth_estimateGas` - Test gas estimation

#### 1.3 Test Block-Related Methods
**Priority**: High (after blocks start being proposed)  
**Methods**:
- `eth_getBlockByNumber` with QR-PoS blocks
- `eth_getBlockByHash` with QR-PoS blocks
- `eth_getBlockTransactionCountByNumber`
- `eth_getBlockTransactionCountByHash`
- Verify Dilithium signatures included in block responses
- Verify QR-PoS consensus fields present

#### 1.4 Web3.py Integration Testing
**Priority**: High  
**File**: Create `tests/integration/test_web3_compatibility.py`  
**Actions**:
```python
# Test Cases:
1. Connect to node via web3.py
2. Get block number
3. Get genesis block details
4. Verify QR-PoS consensus fields accessible
5. Test event filtering
6. Test transaction sending (if applicable)
7. Test contract deployment (if applicable)
8. Verify Dilithium signature handling
```

#### 1.5 Create RPC Test Suite
**Priority**: Medium  
**File**: Create `tests/integration/test_rpc_endpoints.py`  
**Actions**:
- Automated test suite for all RPC methods
- Validation of response formats
- Error handling tests
- Performance benchmarks

**Success Criteria**:
- All tested RPC methods return valid responses
- No hanging or timeout issues
- Web3.py can connect and interact with chain
- HTTP server uses configured port
- All responses match Ethereum JSON-RPC spec

---

## Step 2: IPC Event Delivery Investigation & Fix 🔍

### Objectives
- Verify QRPoSNewBlockEvent broadcasts reaching NewBlockComponent
- Ensure end-to-end event flow working
- Fix any IPC connectivity issues
- Remove all debug stubs and ensure production code paths

### Current State
- Validator broadcasting QRPoSNewBlockEvent when proposing blocks
- NewBlockComponent registered and listening
- IPC debug logging added but investigation incomplete
- Broadcasts completing but reception not confirmed

### Tasks

#### 2.1 Verify Event Registration
**Priority**: High  
**Files**: 
- `trinity/components/builtin/qrpos_validator/component.py`
- `trinity/components/builtin/new_block/component.py`
**Actions**:
1. Confirm QRPoSNewBlockEvent registered in event bus
2. Verify NewBlockComponent subscribed to correct event type
3. Check event bus endpoint connections
4. Review lahja event routing configuration

#### 2.2 Add Comprehensive Event Tracing
**Priority**: High  
**Actions**:
1. Add event send confirmation logging in validator
2. Add event receive logging in NewBlockComponent
3. Log event serialization/deserialization
4. Track event latency (send to receive time)
5. Log IPC socket activity

#### 2.3 Test Event Flow End-to-End
**Priority**: High  
**Test Scenario**:
1. Start 2-node testnet
2. Wait for block proposal (validator's turn)
3. Verify validator logs show broadcast
4. Verify NewBlockComponent logs show reception
5. Verify block imported to chain
6. Verify P2P propagation to peer nodes

#### 2.4 Fix Event Delivery Issues
**Priority**: High  
**Potential Issues to Check**:
- Event bus endpoint naming mismatches
- Event type registration missing
- IPC socket permissions
- Event serialization failures
- Race conditions in component startup
- Event buffer overflow
- Endpoint not connected when event sent

#### 2.5 Remove Debug Code & Stubs
**Priority**: High  
**Actions**:
1. Remove all `# TODO` and `# STUB` markers
2. Remove debug-only code paths
3. Ensure all features use production implementations
4. Verify no mock/fake data in event payloads
5. Clean up excessive logging (keep essential logs)

**Success Criteria**:
- Validator broadcasts visible in logs
- NewBlockComponent receives events (logged)
- Blocks imported successfully
- P2P propagation working
- No timeouts or dropped events
- All code production-ready (no stubs)

---

## Step 3: Fix Genesis Timestamp Issue 🐛

### Objectives
- Fix genesis block timestamp = 0 problem
- Reduce slot numbers to reasonable range (<1000)
- Ensure correct time-based slot calculation

### Current State
- Genesis configuration specifies timestamp
- Genesis import shows timestamp = 0 in logs
- Slot numbers in 88000+ range due to time calculation
- System still functional but aesthetically incorrect

### Tasks

#### 3.1 Debug Genesis Import
**Priority**: Medium  
**File**: `trinity/initialization.py` and genesis import logic  
**Actions**:
1. Add logging to genesis block creation
2. Verify timestamp from JSON config read correctly
3. Check if timestamp overwritten during import
4. Review chain.from_genesis() implementation

#### 3.2 Fix Timestamp Application
**Priority**: Medium  
**Actions**:
1. Ensure genesis timestamp applied to block header
2. Verify timestamp persisted to database
3. Test with fresh genesis import
4. Validate slot calculation uses correct genesis time

#### 3.3 Test Slot Calculation
**Priority**: Medium  
**File**: Validator slot calculation logic  
**Actions**:
1. Verify current_time - genesis_time calculation
2. Test slot number generation with correct genesis
3. Ensure slot numbers start near 0
4. Validate epoch boundaries correct

**Success Criteria**:
- Genesis block shows correct timestamp in logs
- Slot numbers in reasonable range (0-1000)
- Time-based slot calculation correct
- No impact on consensus functionality

---

## Step 4: Phase 3 - Complete Attestation System 🎯

### Objectives
- Broadcast attestations via IPC event bus
- Aggregate attestations from all validators
- Track justified and finalized checkpoints
- Implement fork choice rule based on attestations

### Prerequisites
- ✅ Steps 1-3 completed
- ✅ All systems in production state
- ✅ No known blocking issues

### Phase 3.1: Attestation Broadcasting

#### 4.1.1 Create Attestation Event Type
**Priority**: High  
**File**: Create `trinity/components/builtin/qrpos_validator/events.py`  
**Actions**:
```python
@dataclass
class QRPoSAttestationEvent:
    attestation: Attestation  # Contains slot, block_hash, validator_index, signature
    validator_index: int
    slot: int
    source_checkpoint: Checkpoint
    target_checkpoint: Checkpoint
```

#### 4.1.2 Broadcast Attestations from Validator
**Priority**: High  
**File**: `trinity/components/builtin/qrpos_validator/component.py`  
**Actions**:
1. After creating attestation, broadcast via event bus
2. Include all attestation data in event
3. Log broadcast for debugging
4. Ensure broadcast doesn't block slot timing

#### 4.1.3 Create Attestation Pool Component
**Priority**: High  
**File**: Create `trinity/components/builtin/attestation_pool/component.py`  
**Actions**:
1. New component to receive and store attestations
2. Listen for QRPoSAttestationEvent
3. Maintain in-memory pool organized by slot
4. Validate attestations (signature, slot, validator)
5. Deduplicate attestations from same validator

### Phase 3.2: Attestation Aggregation

#### 4.2.1 Aggregate Attestations per Slot
**Priority**: High  
**File**: Attestation pool aggregation logic  
**Actions**:
1. Group attestations by slot number
2. Track which validators have attested
3. Calculate attestation weight (validator count)
4. Identify majority attestation target

#### 4.2.2 Include Attestations in Blocks
**Priority**: High  
**File**: Block creation in validator  
**Actions**:
1. Query attestation pool when creating block
2. Include attestations for previous slots
3. Add aggregated attestations to block body
4. Update block structure to hold attestations

#### 4.2.3 Validate Attestations in Blocks
**Priority**: High  
**File**: Block import validation  
**Actions**:
1. Verify attestation signatures (Dilithium)
2. Check attestation slot validity
3. Ensure no duplicate attestations
4. Validate validator indices

### Phase 3.3: Justified & Finalized Checkpoints

#### 4.3.1 Track Checkpoint State
**Priority**: High  
**File**: Create checkpoint tracking in chain state  
**Actions**:
1. Store justified checkpoint in chain state
2. Store finalized checkpoint in chain state
3. Update on each epoch boundary
4. Persist to database

#### 4.3.2 Calculate Justification
**Priority**: High  
**Logic**: Block justified when ≥100 validators attest (2/3 of 150)  
**Actions**:
1. Count attestations per block
2. Mark block as justified when threshold met
3. Update chain's justified checkpoint
4. Log justification events

#### 4.3.3 Calculate Finalization
**Priority**: High  
**Logic**: Block finalized when 2 consecutive epochs justified  
**Actions**:
1. Track justified epochs
2. Detect consecutive justification
3. Mark block as finalized
4. Update chain's finalized checkpoint
5. Prune data before finalized checkpoint

### Phase 3.4: Fork Choice Rule

#### 4.4.1 Implement Weight-Based Fork Choice
**Priority**: High  
**File**: Fork choice logic in chain  
**Actions**:
1. Calculate chain weight based on attestations
2. Choose heaviest chain as canonical
3. Handle ties (use block hash comparison)
4. Update chain head on each new attestation

#### 4.4.2 Reorganization Handling
**Priority**: High  
**Actions**:
1. Detect when heavier fork appears
2. Reorg to heavier chain
3. Update validator state
4. Broadcast reorg events
5. Log reorg for monitoring

#### 4.4.3 Finality Protection
**Priority**: High  
**Actions**:
1. Never reorg before finalized checkpoint
2. Reject blocks building on non-finalized chain
3. Implement slashing conditions for violations
4. Add safety checks in block validation

### Phase 3.5: Testing & Validation

#### 4.5.1 Unit Tests
**Priority**: High  
**Files**: Create comprehensive test suites  
**Coverage**:
- Attestation creation and signing
- Attestation validation
- Aggregation logic
- Justification calculation
- Finalization calculation
- Fork choice scenarios
- Reorg handling

#### 4.5.2 Integration Tests
**Priority**: High  
**Scenarios**:
1. Single validator attestations
2. Multiple validators reaching consensus
3. Fork scenarios with competing chains
4. Finalization with sufficient attestations
5. Network partitions and recovery
6. Late attestations handling

#### 4.5.3 Multi-Node Testnet Validation
**Priority**: High  
**Tests**:
1. 2-node testnet: Both validators attesting
2. 5-node testnet: Majority consensus
3. 10-node testnet: Complex fork scenarios
4. Monitor justified/finalized progression
5. Verify fork choice converges
6. Test network resilience

**Success Criteria**:
- All validators broadcasting attestations
- Attestations aggregated correctly
- Blocks justified with 2/3 attestations
- Finalization occurring properly
- Fork choice converging to heaviest chain
- No consensus failures
- All tests passing
- Production-ready code

---

## Implementation Order

### Week 1: RPC & IPC (Steps 1-2)
**Days 1-2**: JSON-RPC testing and fixes
- Fix HTTP port configuration
- Test all core RPC methods
- Fix hanging methods
- Create automated test suite

**Days 3-4**: Web3.py compatibility
- Integration testing with web3.py
- Verify all operations work
- Document any QR-PoS specific considerations

**Days 5-7**: IPC event delivery
- Complete event flow investigation
- Fix any delivery issues
- Remove all stubs and debug code
- Verify production readiness

### Week 2: Genesis Fix & Phase 3.1 (Steps 3-4.1)
**Days 1-2**: Genesis timestamp fix
- Debug and fix timestamp issue
- Validate slot calculations
- Test with fresh genesis

**Days 3-7**: Attestation broadcasting
- Create attestation event types
- Implement broadcasting from validator
- Create attestation pool component
- Test attestation reception

### Week 3: Phase 3.2-3.3 (Aggregation & Checkpoints)
**Days 1-3**: Attestation aggregation
- Aggregate attestations per slot
- Include in blocks
- Validate in block import

**Days 4-7**: Justification & finalization
- Track checkpoint state
- Calculate justification
- Calculate finalization
- Persist state

### Week 4: Phase 3.4-3.5 (Fork Choice & Testing)
**Days 1-3**: Fork choice implementation
- Weight-based fork choice
- Reorg handling
- Finality protection

**Days 4-7**: Testing & validation
- Unit tests
- Integration tests
- Multi-node testnet validation
- Performance testing
- Documentation

---

## Validation Checklist

Before considering Phase 3 complete, verify:

### Functionality
- [ ] All RPC methods working (no stubs)
- [ ] Web3.py fully compatible
- [ ] IPC events delivered reliably
- [ ] Attestations broadcast every slot
- [ ] Attestations aggregated correctly
- [ ] Blocks include attestations
- [ ] Justification calculated correctly
- [ ] Finalization occurring properly
- [ ] Fork choice converging correctly
- [ ] Reorgs handled safely

### Code Quality
- [ ] No TODO/STUB/FIXME markers
- [ ] All debug code removed or configurable
- [ ] Production error handling
- [ ] Comprehensive logging
- [ ] Code documented
- [ ] Type hints complete

### Testing
- [ ] Unit tests passing
- [ ] Integration tests passing
- [ ] Multi-node tests passing
- [ ] Edge cases covered
- [ ] Performance acceptable

### Documentation
- [ ] API documentation complete
- [ ] Architecture documented
- [ ] Consensus rules documented
- [ ] Operator guide written
- [ ] Troubleshooting guide created

---

## Current Focus: START WITH STEP 1

**Immediate Next Actions:**
1. Fix HTTP server port configuration issue
2. Test all core JSON-RPC methods systematically
3. Fix any hanging or timeout issues
4. Create web3.py integration test script
5. Document any QR-PoS specific RPC considerations

**Success Metric for Step 1:**
All standard Ethereum JSON-RPC methods working correctly with web3.py, no stubs, production-ready.
