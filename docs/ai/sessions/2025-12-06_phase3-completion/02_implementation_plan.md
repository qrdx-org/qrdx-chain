# Implementation Plan for Phase 3 Completion

## Date
December 6, 2025

## Priority Order

### 1. Integrate Fork Choice with HeaderDB (HIGH - 2 days)

**Problem**: Fork choice logic exists but canonical head selection still uses simple score comparison

**Current Code** (`py-evm/eth/db/header.py`, line 433-438):
```python
if score > head_score:
    return cls._set_as_canonical_chain_head(
        db, curr_chain_head, genesis_parent_hash
    )
```

**Solution**: Modify `_persist_header_chain` to use weight-based fork choice for QR-PoS blocks

**Implementation Steps**:

1. Add method to check if weight exists for a block (indicates QR-PoS):
```python
# In ChainDB
def has_qrpos_weight(self, block_hash: Hash32) -> bool:
    key = SchemaV1.make_qrpos_block_weight_key(block_hash)
    return key in self.db
```

2. Modify `_persist_header_chain` to use fork choice when weights available:
```python
@classmethod
def _persist_header_chain(
    cls,
    db: DatabaseAPI,
    headers: Iterable[BlockHeaderAPI],
    genesis_parent_hash: Hash32,
) -> Tuple[Tuple[BlockHeaderAPI, ...], Tuple[BlockHeaderAPI, ...]]:
    # ... existing code ...
    
    try:
        previous_canonical_head = cls._get_canonical_head_hash(db)
        head_score = cls._get_score(db, previous_canonical_head)
    except CanonicalHeadNotFound:
        return cls._set_as_canonical_chain_head(
            db, curr_chain_head, genesis_parent_hash
        )
    
    # NEW: Check if this is QR-PoS (has weight)
    curr_weight_key = SchemaV1.make_qrpos_block_weight_key(curr_chain_head.hash)
    prev_weight_key = SchemaV1.make_qrpos_block_weight_key(previous_canonical_head)
    
    # If both blocks have weights, use weight-based fork choice
    if curr_weight_key in db and prev_weight_key in db:
        import rlp
        from rlp.sedes import big_endian_int
        
        curr_weight = rlp.decode(db[curr_weight_key], sedes=big_endian_int)
        prev_weight = rlp.decode(db[prev_weight_key], sedes=big_endian_int)
        
        # Use weight comparison instead of score
        if curr_weight > prev_weight:
            return cls._set_as_canonical_chain_head(
                db, curr_chain_head, genesis_parent_hash
            )
        elif curr_weight == prev_weight:
            # Tie-breaker: lower hash wins (deterministic)
            if curr_chain_head.hash < previous_canonical_head:
                return cls._set_as_canonical_chain_head(
                    db, curr_chain_head, genesis_parent_hash
                )
        # Otherwise keep current head
        return (), ()
    
    # Fall back to score-based (PoW) for non-QR-PoS blocks
    if score > head_score:
        return cls._set_as_canonical_chain_head(
            db, curr_chain_head, genesis_parent_hash
        )

    return (), ()
```

**Files to Modify**:
- `py-evm/eth/db/header.py` - Modify `_persist_header_chain` method (lines 368-438)
- `py-evm/eth/db/chain.py` - Add `has_qrpos_weight` convenience method

**Testing**:
- Create two competing blocks with different weights
- Verify heaviest chain becomes canonical
- Verify tie-breaking works
- Verify PoW blocks still work (backward compatibility)

**Impact**: 🔴 CRITICAL - This is the core of Phase 3 fork choice

---

### 2. Fix Genesis Timestamp (MEDIUM - 1 day)

**Problem**: Genesis block has timestamp = 0, causing high slot numbers

**Investigation Steps**:
1. Check genesis JSON file for timestamp value
2. Trace genesis import in `trinity/initialization.py`
3. Find where timestamp gets overwritten to 0

**Likely Issue**: Genesis header creation not applying timestamp from config

**Solution**: Ensure timestamp from genesis config is applied to genesis header

**Files to Check**:
- `trinity/initialization.py` - Genesis import logic
- Genesis JSON file - Verify timestamp is set
- Chain initialization code

**Testing**:
- Create fresh genesis with timestamp = current time
- Verify slot numbers are reasonable (0-100)
- Verify time-based slot calculation works

**Impact**: 🟡 MEDIUM - Affects aesthetics and time calculations but not core functionality

---

### 3. Load Validator Set from Genesis (HIGH - 1 day)

**Problem**: TODO at line 184 in new_block/component.py - not loading validator set

**Current Code**:
```python
# TODO: Load actual validator set from genesis/config
# For now, we trust blocks from local validator
```

**Solution**: Load validator set from genesis config and validate proposers

**Implementation**:

1. Add validator set to genesis config:
```python
# In genesis JSON
{
    "validators": [
        {
            "index": 0,
            "pubkey": "0x...",
            "address": "0x...",
            "stake": "100000000000000000000000"
        },
        // ... 149 more
    ]
}
```

2. Load in NewBlockService:
```python
# Load validator set from genesis
genesis_header = chain.chaindb.get_canonical_block_header_by_number(0)
genesis_config = get_genesis_config(self._boot_info.trinity_config)
validators = genesis_config['validators']

# Create ValidatorSet
from eth.consensus.qrpos import Validator, ValidatorSet, ValidatorStatus
validator_set = ValidatorSet()
for v in validators:
    validator = Validator(
        index=v['index'],
        pubkey=bytes.fromhex(v['pubkey'][2:]),
        address=Address(bytes.fromhex(v['address'][2:])),
        stake=int(v['stake']),
        status=ValidatorStatus.ACTIVE,
    )
    validator_set.add_validator(validator)
```

3. Use validator set to validate blocks:
```python
# Extract proposer from block
slot = int.from_bytes(header.extra_data[:8], 'big')
validator_index = int.from_bytes(header.extra_data[8:16], 'big')

# Verify correct proposer
expected_proposer = slot % len(validator_set.validators)
if validator_index != expected_proposer:
    raise ValidationError(f"Invalid proposer: expected {expected_proposer}, got {validator_index}")

# Verify Dilithium signature
validator = validator_set.validators[validator_index]
# TODO: Add signature verification when integrated
```

**Files to Modify**:
- `trinity/components/builtin/new_block/component.py` - Load validator set, validate blocks
- Genesis JSON file - Add validators array
- May need to update genesis creation scripts

**Testing**:
- Try to import block from wrong proposer (should fail)
- Verify correct proposer blocks are accepted
- Test with 3-node and 150-validator configs

**Impact**: 🔴 HIGH - Security issue, blocks not properly validated

---

### 4. Weight Cache Management (LOW - 0.5 days)

**Problem**: Unbounded cache in `FinalityGadget._block_weights`

**Current Code**:
```python
class FinalityGadget:
    def __init__(self):
        self._block_weights: Dict[Hash32, int] = {}  # Unbounded!
```

**Solution**: Add LRU cache or periodic clearing

**Option A - LRU Cache**:
```python
from functools import lru_cache
from collections import OrderedDict

class LRUCache:
    def __init__(self, max_size=1000):
        self.cache = OrderedDict()
        self.max_size = max_size
    
    def get(self, key):
        if key in self.cache:
            self.cache.move_to_end(key)
            return self.cache[key]
        return None
    
    def put(self, key, value):
        if key in self.cache:
            self.cache.move_to_end(key)
        self.cache[key] = value
        if len(self.cache) > self.max_size:
            self.cache.popitem(last=False)

class FinalityGadget:
    def __init__(self):
        self._block_weights = LRUCache(max_size=1000)
```

**Option B - Periodic Clearing**:
```python
class FinalityGadget:
    def __init__(self):
        self._block_weights: Dict[Hash32, int] = {}
        self._weight_cache_size = 0
        self.MAX_CACHE_SIZE = 10000
    
    def calculate_block_weight(self, block_hash, attestations, validator_set):
        # ... calculation ...
        
        self._block_weights[block_hash] = weight
        self._weight_cache_size += 1
        
        # Clear old entries periodically
        if self._weight_cache_size > self.MAX_CACHE_SIZE:
            # Keep only recent finalized + justified checkpoints
            self._block_weights = {
                self.justified_hash: self._block_weights.get(self.justified_hash, 0),
                self.finalized_hash: self._block_weights.get(self.finalized_hash, 0),
            }
            self._weight_cache_size = len(self._block_weights)
```

**Files to Modify**:
- `py-evm/eth/consensus/qrpos.py` - Modify FinalityGadget class

**Testing**:
- Run testnet for extended period
- Monitor memory usage
- Verify cache doesn't grow unbounded

**Impact**: 🟢 LOW - Memory leak prevention, not urgent

---

### 5. Verify Ancestry Checking (VERIFICATION - 0.5 days)

**Task**: Verify `_extends_from_finalized()` is actually being called

**Check Points**:
1. Fork choice `get_head()` method calls `_extends_from_finalized()`
2. Validator component uses fork choice when importing blocks
3. NewBlockComponent uses fork choice for peer blocks
4. Logs show ancestry checking in action

**Files to Check**:
- `py-evm/eth/consensus/qrpos.py` - ForkChoice.get_head()
- `trinity/components/builtin/qrpos_validator/component.py`
- `trinity/components/builtin/new_block/component.py`

**Testing**:
- Create fork past finalized checkpoint
- Verify it's rejected
- Check logs for ancestry verification messages

**Impact**: 🟡 MEDIUM - Safety verification

---

### 6. Live Multi-Node Testnet (VALIDATION - 1 day)

**Task**: Run comprehensive 3-node testnet and verify Phase 3 working

**Test Scenarios**:

1. **Basic Operation** (30 minutes)
   - Start 3 nodes
   - Verify all nodes produce blocks
   - Verify attestations propagate
   - Check block synchronization

2. **Finality Progression** (30 minutes)
   - Monitor justified checkpoint advancing
   - Monitor finalized checkpoint advancing
   - Verify 2/3 supermajority needed
   - Check checkpoint persistence

3. **Fork Choice** (30 minutes)
   - Create competing blocks (pause one node)
   - Verify heaviest chain wins
   - Check weight calculations
   - Verify convergence

4. **Long Run** (1+ hour)
   - Run testnet for extended period
   - Monitor for memory leaks
   - Check for crashes or stalls
   - Verify consistent finality

**Success Criteria**:
- All 3 nodes synchronized
- Finality progressing every epoch
- Fork choice working correctly
- No crashes or errors
- Attestations aggregating properly

**Impact**: 🔴 CRITICAL - Final validation before production

---

## Implementation Schedule

### Day 1: Fork Choice Integration
- Morning: Implement weight-based fork choice in `_persist_header_chain`
- Afternoon: Test with competing blocks, verify tie-breaking
- Evening: Integration testing with validator component

### Day 2: Genesis Timestamp & Validator Set
- Morning: Debug and fix genesis timestamp issue
- Afternoon: Implement validator set loading from genesis
- Evening: Test block validation with correct/incorrect proposers

### Day 3: Testing & Validation
- Morning: Verify ancestry checking, add weight cache management
- Afternoon: Set up 3-node testnet
- Evening: Run test scenarios and monitor

### Day 4: Final Validation & Documentation
- Morning: Long-running testnet validation
- Afternoon: Fix any issues found
- Evening: Create completion documentation

## Success Metrics

- [ ] Fork choice using attestation weight (not just score)
- [ ] Genesis timestamp correct
- [ ] Slot numbers reasonable
- [ ] Validator set loaded from genesis
- [ ] Block proposers validated
- [ ] Weight cache bounded
- [ ] Ancestry checking verified
- [ ] 3-node testnet stable for 1+ hour
- [ ] Finality progressing correctly
- [ ] No memory leaks or crashes
- [ ] All TODOs resolved

## Risks & Mitigation

**Risk 1**: Fork choice changes break existing PoW compatibility
- Mitigation: Only use weight-based fork choice when weights exist
- Fallback to score-based for non-QR-PoS blocks

**Risk 2**: Validator set loading requires genesis format changes
- Mitigation: Make validators optional in genesis, create migration guide
- Test with existing genesis files

**Risk 3**: testnet reveals consensus issues
- Mitigation: Comprehensive logging, ability to pause and inspect state
- Have rollback plan for any database changes

## Notes

- Fork choice integration is most critical and complex
- Genesis timestamp is simpler but important for user experience
- Validator set loading is security-critical
- Testing is essential before declaring Phase 3 complete
