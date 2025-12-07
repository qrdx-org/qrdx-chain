# Issues & Solutions Log

## Issue #1: Import Shadowing in header.py
**Severity**: CRITICAL  
**Discovered**: 2025-12-06 15:30  
**Impact**: Runtime UnboundLocalError preventing genesis block creation

**Problem**:
```python
# Inside _persist_header_chain() method (line ~436):
from eth.db.schema import SchemaV1
import rlp  # ❌ Shadows module-level import
from rlp.sedes import big_endian_int

# Earlier in same method (line ~390):
rlp.encode(curr_chain_head)  # ❌ UnboundLocalError: rlp not yet defined
```

**Root Cause**: Inline `import rlp` statement shadowed the module-level import, causing earlier references to `rlp` to fail since Python treats it as a local variable that hasn't been assigned yet.

**Solution**: Moved all imports to top of file
```python
# At top of header.py:
import rlp  # ✅ Module-level
from rlp.sedes import big_endian_int  # ✅ Module-level
from eth.db.schema import SchemaV1  # Already there

# In method:
curr_weight = rlp.decode(db[curr_weight_key], sedes=big_endian_int)  # ✅ Works
```

**Status**: ✅ FIXED  
**Files Modified**: `py-evm/eth/db/header.py`

---

## Issue #2: Missing Tuple Import in QRPoS Validator
**Severity**: HIGH  
**Discovered**: 2025-12-06 15:20  
**Impact**: Module import failure preventing validator component from loading

**Problem**:
```python
# component.py line 277:
) -> Tuple[BlockHeader, tuple, tuple]:  # ❌ NameError: name 'Tuple' is not defined
```

**Root Cause**: `Tuple` type was used in type annotation but not imported from `typing`

**Solution**: Added import
```python
# Line 8:
from typing import Optional, List, cast, Tuple  # ✅ Added Tuple
```

**Status**: ✅ FIXED  
**Files Modified**: `trinity/components/builtin/qrpos_validator/component.py`

---

## Issue #3: Genesis Timestamp = 0 Bug
**Severity**: HIGH  
**Discovered**: 2025-12-06 16:00  
**Impact**: Slot numbers ~88000+ instead of 0-300, confusing debugging

**Problem**:
```python
# start_local_testnet.py used wrong genesis format:
genesis = {
    "config": {"chainId": 1337},  # ❌ Geth format, not EIP-1085
    "timestamp": "0x0",  # ❌ Hardcoded to 0
}
```

**Root Causes**:
1. Script used Geth genesis format instead of Trinity's required EIP-1085 format
2. Even in correct sections, timestamp was hardcoded to `"0x0"`
3. Trinity's `extract_genesis_params()` expects EIP-1085 structure

**Solution**: Converted to EIP-1085 format with proper timestamp
```python
genesis = {
    "version": "1",  # ✅ EIP-1085 marker
    "params": {...},  # ✅ Chain parameters
    "genesis": {
        "timestamp": f"0x{int(time.time()) - 600:x}",  # ✅ Recent timestamp
        ...
    },
    "accounts": {...}  # ✅ EIP-1085 accounts section
}
```

**Verification**: py-evm's `Chain.from_genesis()` correctly preserves timestamp when provided in params dict

**Expected Outcome**:
- Genesis block timestamp: ~10 minutes before node start
- Initial slot number: ~300 (600 seconds ÷ 2 seconds/slot)
- Predictable, debuggable slot progression

**Status**: ✅ FIXED  
**Files Modified**: `scripts/start_local_testnet.py`

---

## Issue #4: Validator Set Not Loaded for Block Validation (TODO)
**Severity**: MEDIUM  
**Discovered**: Pre-existing (found in code audit)  
**Impact**: Security - blocks from any source trusted without signature validation

**Problem**:
```python
# new_block/component.py line 184:
# TODO: Load actual validator set from genesis/config
# For now, we trust blocks from local validator
```

**Root Cause**: Block validation code lacked access to validator public keys needed to verify Dilithium signatures

**Solution**: Load validator set deterministically using same method as QRPoSValidator component
```python
# Generate same validator set as validators use:
NUM_VALIDATORS = int(os.environ.get('QRDX_NUM_VALIDATORS', '3'))
for i in range(NUM_VALIDATORS):
    seed = hashlib.sha256(f"qrdx-testnet-validator-{i}".encode()).digest()
    _, validator_pubkey = generate_dilithium_keypair(seed=seed)
    validator = Validator(index=i, public_key=validator_pubkey, ...)

# Validate signature:
validate_qrpos_block(header, signature, validator_pubkeys, genesis_time)
```

**Why This Works**:
- Validators generate deterministic keypairs from same seed pattern
- NewBlockComponent can regenerate same public keys
- No need for database/IPC communication for validator set
- Matches existing validator initialization pattern

**Status**: ✅ FIXED  
**Files Modified**: `trinity/components/builtin/new_block/component.py`

---

## Lessons Learned

### 1. Python Import Shadowing
- **Always** import at module level, not inline
- Python treats names as local variables if assigned anywhere in function scope
- Shadowing errors are silent until runtime

### 2. Genesis Format Compatibility
- Trinity requires strict EIP-1085 format
- Schema validation enforces `"version"`, `"params"`, `"genesis"`, `"accounts"` structure
- Geth format (`"config"`) is incompatible
- Always validate genesis format against Trinity's schema

### 3. Timestamp Propagation
- py-evm's `Chain.from_genesis()` correctly preserves timestamp when provided
- Bug was in INPUT data (wrong format + hardcoded 0), not in processing code
- Always trace data flow from source (JSON) to destination (block header)

### 4. Deterministic Keypair Generation
- Seeded keypair generation enables validator set reconstruction
- No database needed for validator public keys
- Simplifies component initialization
- Pattern: `seed = hash(f"prefix-{index}") -> keypair`

### 5. Code Archaeology
- Read existing patterns before implementing new solutions
- QRPoSValidatorComponent already had validator set generation logic
- Reusing existing patterns ensures consistency
- Check for TODOs during gap analysis - they often indicate critical missing features
