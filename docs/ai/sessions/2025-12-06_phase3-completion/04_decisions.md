# Key Decisions

## Decision 1: Weight-Based Fork Choice Integration Strategy
**Date**: 2025-12-06 14:00  
**Decision**: Integrate fork choice by modifying HeaderDB._persist_header_chain() rather than replacing entire canonical head selection logic  
**Rationale**:  
- Minimal invasive changes to existing codebase
- Maintains backward compatibility with PoW blocks (score-based)
- Uses database key existence as clean discriminator between QR-PoS and PoW blocks
- Allows gradual transition and coexistence of consensus mechanisms

**Alternative Considered**: Create separate QRPoSHeaderDB subclass  
**Why Rejected**: Would require changes throughout Trinity codebase, more complex migration path

**Impact**:  
- ✅ QR-PoS blocks use attestation weight for fork choice
- ✅ PoW blocks continue using score (backward compatible)  
- ✅ Deterministic tie-breaker (hash comparison)
- ✅ Clean separation via database key schema

## Decision 2: Import Organization in header.py
**Date**: 2025-12-06 15:30  
**Decision**: Move all imports to top of file, remove inline imports  
**Rationale**:  
- Inline `import rlp` caused variable shadowing bug (UnboundLocalError)
- Module-level imports are Python best practice
- Prevents future shadowing issues
- Improves code readability

**Bug Fixed**: `rlp` import inside `_persist_header_chain()` shadowed module-level `rlp`, causing earlier uses of `rlp.encode()` to fail

**Impact**:  
- ✅ Eliminated critical runtime error
- ✅ Improved code maintainability
- ✅ Follows Python conventions

## Decision 3: Genesis Format - EIP-1085 vs Geth Format
**Date**: 2025-12-06 16:00  
**Decision**: Convert start_local_testnet.py to use EIP-1085 genesis format  
**Rationale**:  
- Trinity requires EIP-1085 format (has schema validation)
- Geth format (`"config"`) not compatible with Trinity's `extract_genesis_params()`
- `start_multi_node_testnet.sh` already uses EIP-1085 correctly
- Consistency across all launch scripts

**Root Cause Identified**: Genesis timestamp=0 bug caused by two issues:
1. `start_local_testnet.py` used wrong genesis format
2. Even in correct format, timestamp was hardcoded to `"0x0"`

**Fix Applied**:
```python
# OLD (Geth format, timestamp=0):
genesis = {
    "config": {"chainId": 1337},
    "timestamp": "0x0",
    ...
}

# NEW (EIP-1085 format, proper timestamp):
genesis = {
    "version": "1",
    "params": {"chainId": "0x539", ...},
    "genesis": {
        "timestamp": f"0x{int(time.time()) - 600:x}",
        ...
    },
    "accounts": {...}
}
```

**Impact**:  
- ✅ Genesis timestamp now set to (current_time - 10 minutes)
- ✅ Slot numbers will be reasonable (0-300 range instead of 88000+)
- ✅ Consistent with multi-node testnet script
- ✅ Proper Trinity EIP-1085 validation

## Decision 4: Genesis Timestamp Strategy
**Date**: 2025-12-06 16:05  
**Decision**: Use `current_time - 600` (10 minutes ago) for genesis timestamp  
**Rationale**:  
- Allows for genesis state preparation time
- Keeps slot numbers in reasonable range (hundreds, not tens of thousands)
- Matches pattern used in `start_multi_node_testnet.sh`
- Provides buffer for node startup synchronization

**Alternative Considered**: Use exact current time  
**Why Rejected**: Could cause slot number mismatches if nodes start at slightly different times, no buffer for initialization

**Impact**:  
- Slot numbers at startup: ~300 (10 minutes ÷ 2 seconds/slot)
- Predictable and debuggable slot progression
- Consistent across single and multi-node testnets
